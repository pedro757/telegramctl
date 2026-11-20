import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { parseArgs } from 'node:util';
import { join } from 'node:path';
import type { CompactDefinition, CompactField, Schema } from '../src/tl.ts';

const COMMIT = '850fb90eb6db96c124b6da1349060f9ed00f4fe4';
const REPOSITORY = 'https://github.com/telegramdesktop/tdesktop';
const SCHEME_DIR = 'Telegram/SourceFiles/mtproto/scheme';
const INPUTS = {
  'api.tl': '76922ce265441d3f2f5188f56b69b41e1cb11354657ea547707507f8c3b93826',
  'mtproto.tl':
    '40c10255afb6cfcbcfc190a457a53b66ec9e410f6418cd97cc4c276709a739a9',
} as const;
const MAX_SIZE = 1024 * 1024;
type SourceName = keyof typeof INPUTS;

const { values } = parseArgs({
  options: { source: { type: 'string' }, fetch: { type: 'boolean' } },
});
if (Boolean(values.source) === Boolean(values.fetch))
  throw new Error(
    'Use --source <directory containing both schema files> or --fetch.',
  );

const digest = (source: Buffer | string) =>
  createHash('sha256').update(source).digest('hex');
async function readTl(name: SourceName) {
  let source;
  if (values.source) source = await readFile(join(values.source, name));
  else {
    const url = 'https://raw.githubusercontent.com/telegramdesktop/tdesktop';
    const response = await fetch(`${url}/${COMMIT}/${SCHEME_DIR}/${name}`, {
      signal: AbortSignal.timeout(30_000),
      redirect: 'error',
    });
    if (!response.ok || !response.body)
      throw new Error(`Pinned schema download failed: ${name}`);
    const chunks: Buffer[] = [];
    let size = 0;
    for await (const chunk of response.body) {
      size += chunk.length;
      if (size > MAX_SIZE)
        throw new Error(`Schema download exceeds the size limit: ${name}`);
      chunks.push(Buffer.from(chunk));
    }
    source = Buffer.concat(chunks, size);
  }
  if (source.length > MAX_SIZE || digest(source) !== INPUTS[name])
    throw new Error(`Pinned schema SHA-256 mismatch or size limit: ${name}`);
  return source.toString('utf8');
}

type Field = {
  name: string;
  type: string;
  vector?: 'Vector' | 'vector';
  flag?: [index: number, bit: number];
};
type Definition = {
  name: string;
  id: number;
  result: string;
  method: boolean;
  fields: Field[];
};
const title = (value: string) => value[0].toUpperCase() + value.slice(1);
const camel = (value: string) =>
  value.replace(/_([A-Za-z])/g, (_, letter: string) => letter.toUpperCase());
function constructorName(value: string) {
  const start = value.lastIndexOf('.') + 1;
  return value.slice(0, start) + title(camel(value.slice(start)));
}

// The transport schema uses TL "string" for these octet sequences, not UTF-8.
const binaryFields: Readonly<Record<string, readonly string[]>> = {
  resPQ: ['pq'],
  p_q_inner_data: ['pq', 'p', 'q'],
  p_q_inner_data_dc: ['pq', 'p', 'q'],
  p_q_inner_data_temp: ['pq', 'p', 'q'],
  p_q_inner_data_temp_dc: ['pq', 'p', 'q'],
  req_DH_params: ['p', 'q', 'encrypted_data'],
  server_DH_params_ok: ['encrypted_answer'],
  server_DH_inner_data: ['dh_prime', 'g_a'],
  client_DH_inner_data: ['g_b'],
  set_client_DH_params: ['encrypted_data'],
  msgs_state_info: ['info'],
  msgs_all_info: ['info'],
};
const coreDeclarations = new Set([
  'int ? = Int;',
  'long ? = Long;',
  'double ? = Double;',
  'string ? = String;',
  'int128 4*[ int ] = Int128;',
  'int256 8*[ int ] = Int256;',
  'vector {t:Type} # [ t ] = Vector t;',
  'vector#1cb5c415 {t:Type} # [ t ] = Vector t;',
]);

function parseTl(source: string, filename: SourceName): Definition[] {
  const definitions: Definition[] = [];
  let method = false;
  for (const [index, raw] of source.split(/\r?\n/).entries()) {
    const line = raw.split('//', 1)[0].trim();
    if (!line || coreDeclarations.has(line)) continue;
    // These ID-less declarations describe Desktop's fake-TLS transport.
    if (filename === 'mtproto.tl' && /^tls\w+ /.test(line)) continue;
    if (line === '---types---' || line === '---functions---') {
      method = line === '---functions---';
      continue;
    }
    const fail = () => new Error(`${filename}:${index + 1}: invalid TL`);
    const declaration = /^([\w.]+)#([a-f0-9]{1,8})(.*?) = ([\w.<>]+);$/.exec(
      line,
    );
    if (!declaration) throw fail();
    const [, name, id, argumentsText, result] = declaration;
    const fields: Field[] = [];
    const flags = new Map<string, number>();
    for (const token of argumentsText.trim().split(/\s+/).filter(Boolean)) {
      if (token === '{X:Type}') continue;
      const field = /^(\w+):(?:(\w+)\.(\d{1,2})\?)?!?([\w.#<>]+)$/.exec(token);
      if (!field) throw fail();
      const [, fieldName, flagWord, bitText, rawType] = field;
      const vector = /^(Vector|vector)<([\w.]+)>$/.exec(rawType);
      if (!vector && rawType.includes('<')) throw fail();
      const isBinary =
        rawType === 'string' &&
        Object.hasOwn(binaryFields, name) &&
        binaryFields[name].includes(fieldName);
      const entry: Field = {
        name: fieldName === 'srp_B' ? fieldName : camel(fieldName),
        type: vector?.[2] ?? (isBinary ? 'bytes' : rawType),
        vector: vector
          ? vector[1] === 'Vector'
            ? 'Vector'
            : 'vector'
          : undefined,
      };
      if (flagWord) {
        const word = flags.get(flagWord);
        const bit = Number(bitText);
        if (word === undefined || bit > 31) throw fail();
        entry.flag = [word, bit];
      }
      if (entry.type === '#') flags.set(fieldName, fields.length);
      fields.push(entry);
    }
    definitions.push({
      name: constructorName(name),
      id: Number.parseInt(id, 16),
      result,
      method,
      fields,
    });
  }
  return definitions;
}

const [api, transport] = await Promise.all([
  readTl('api.tl'),
  readTl('mtproto.tl'),
]);
const layer = Number(/^\/\/ LAYER (\d+)\s*$/m.exec(api)?.[1]);
if (layer !== 232) throw new Error('Unexpected API layer');
const upstream = [
  ...parseTl(api, 'api.tl'),
  ...parseTl(transport, 'mtproto.tl'),
];
const requests = new Set([
  'ReqPqMulti',
  'ReqDHParams',
  'SetClientDHParams',
  'DestroyAuthKey',
  'InvokeWithLayer',
  'InitConnection',
  'InvokeWithoutUpdates',
  'help.GetConfig',
  'auth.SendCode',
  'auth.SignIn',
  'auth.CheckPassword',
  'auth.LogOut',
  'auth.ExportAuthorization',
  'auth.ImportAuthorization',
  'account.GetPassword',
  'users.GetUsers',
  'users.GetFullUser',
  'contacts.ResolveUsername',
  'messages.GetDialogs',
  'messages.GetHistory',
  'messages.GetMessages',
  'messages.DeleteMessages',
  'messages.Search',
  'messages.SearchGlobal',
  'messages.SendMessage',
  'messages.SendMedia',
  'upload.SaveFilePart',
  'upload.SaveBigFilePart',
  'upload.GetFile',
  'messages.GetFullChat',
  'channels.GetFullChannel',
  'channels.GetMessages',
  'channels.DeleteMessages',
  'channels.GetParticipants',
  'channels.GetParticipant',
  'account.UpdateNotifySettings',
  'messages.DeleteChatUser',
  'channels.EditBanned',
  'channels.EditAdmin',
  'messages.EditChatAdmin',
  'messages.EditChatCreator',
  'messages.GetDialogFilters',
  'messages.UpdateDialogFilter',
]);
// Compute the transitive type closure, not just a filtered package manifest.
// Polymorphic Updates/Message responses necessarily retain many data variants;
// unrelated request definitions and unreachable constructor data are removed.
const constructors = upstream.filter((definition) => !definition.method);
const byResult = new Map<string, Definition[]>();
const byName = new Map(
  upstream.map((definition) => [definition.name, definition]),
);
const ids = new Set(upstream.map((definition) => definition.id));
if (byName.size !== upstream.length || ids.size !== upstream.length)
  throw new Error('Duplicate upstream schema definition');
for (const definition of constructors) {
  const group = byResult.get(definition.result);
  if (group) group.push(definition);
  else byResult.set(definition.result, [definition]);
}
const selected = new Set<Definition>(),
  work: Definition[] = [];
const addDefinition = (definition: Definition) => {
  if (!selected.has(definition)) {
    selected.add(definition);
    work.push(definition);
  }
};
for (const name of requests) {
  const definition = byName.get(name);
  if (!definition?.method) throw new Error(`Missing required request: ${name}`);
  addDefinition(definition);
}
for (const name of [
  'PQInnerDataDc',
  'ClientDHInnerData',
  'ServerDHInnerData',
  'MsgsAck',
  'BadServerSalt',
  'BadMsgNotification',
  'NewSessionCreated',
  'MsgDetailedInfo',
  'MsgNewDetailedInfo',
  'MsgsStateReq',
  'MsgsStateInfo',
  'MsgsAllInfo',
  'MsgResendReq',
  'Pong',
  'RpcError',
]) {
  const definition = byName.get(name);
  if (!definition || definition.method)
    throw new Error(`Missing required service/inner constructor: ${name}`);
  addDefinition(definition);
}
const bareTypes = new Set([
  'int',
  'long',
  'int128',
  'int256',
  'double',
  'string',
  'bytes',
  'true',
]);
const primitive = new Set(['#', 'Bool', 'X', 'Object', ...bareTypes]);
function addType(type: string) {
  while (type.startsWith('Vector<') && type.endsWith('>'))
    type = type.slice(7, -1);
  if (primitive.has(type)) return;
  const bare = byName.get(type);
  const matches = byResult.get(type) ?? (bare && !bare.method ? [bare] : []);
  if (!matches.length) throw new Error(`Unresolved schema type: ${type}`);
  for (const definition of matches) addDefinition(definition);
}
while (work.length) {
  const definition = work.pop()!;
  addType(definition.result);
  for (const field of definition.fields) addType(field.type);
}
const strings: string[] = [];
const indices = new Map<string, number>();
function intern(value: string) {
  const known = indices.get(value);
  if (known !== undefined) return known;
  const index = strings.length;
  strings.push(value);
  indices.set(value, index);
  return index;
}
function compactField(field: Field): CompactField {
  const name = intern(field.name);
  if (field.type === '#') return [name, -1, 8];
  const type = intern(field.type);
  // Keep the bit layout in sync with the TL codec.
  const bits =
    (field.vector ? 1 : 0) |
    (field.flag ? 2 : 0) |
    (bareTypes.has(field.type) ? 4 : 0) |
    (field.vector === 'Vector' ? 16 : 0);
  return field.flag ? [name, type, bits, ...field.flag] : [name, type, bits];
}
const definitions = upstream
  .filter((definition) => selected.has(definition))
  .map(({ name, id, result, method, fields }): CompactDefinition => {
    const entry: CompactDefinition = [intern(name), id, intern(result), method];
    if (fields.length) entry.push(fields.map(compactField));
    return entry;
  });
const schema: Schema = {
  layer,
  strings,
  definitions,
};
const data = JSON.stringify(schema) + '\n';
const constructorCount = definitions.length - requests.size;
await mkdir(new URL('../src/protocol/', import.meta.url), { recursive: true });
await writeFile(new URL('../src/protocol/schema.json', import.meta.url), data);
await writeFile(
  new URL('../src/protocol/provenance.json', import.meta.url),
  JSON.stringify(
    {
      repository: REPOSITORY,
      commit: COMMIT,
      sourceDirectory: SCHEME_DIR,
      sourceSha256: INPUTS,
      schemaSha256: digest(data),
      layer,
      constructors: constructorCount,
      upstreamConstructors: constructors.length,
      upstreamRequests: upstream.length - constructors.length,
      requests: [...requests].sort(),
      localAdjustments: [
        'Binary transport fields declared as string are represented as bytes',
        'TL names are normalized to the local codec naming convention',
      ],
    },
    null,
    2,
  ) + '\n',
);
console.log(
  `Generated layer ${layer}: ${constructorCount}` +
    ` data constructors, ${requests.size} RPC definitions,` +
    ` ${Buffer.byteLength(data)} bytes.`,
);

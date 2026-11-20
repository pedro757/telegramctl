import { readFileSync } from 'node:fs';
import { gunzipSync } from 'node:zlib';
import { protocolError } from './common.ts';

export type CompactField = [number, number, number, number?, number?];
export type CompactDefinition = [
  name: number,
  id: number,
  result: number,
  method: boolean,
  fields?: CompactField[],
];
export type Schema = {
  layer: number;
  strings: string[];
  definitions: CompactDefinition[];
};
const schema: Schema = JSON.parse(
  readFileSync(new URL('./protocol/schema.json', import.meta.url), 'utf8'),
);
export const LAYER = schema.layer;
export const MAX_BYTES = 8 * 1024 * 1024;
const MAX_ITEMS = 100_000,
  MAX_DEPTH = 64,
  MAX_NODES = 250_000;
const VECTOR = 0x1cb5c415,
  TRUE = 0x997275b5,
  FALSE = 0xbc799737,
  GZIP = 0x3072cfa1;
// Field bits from the generated schema, not the flags carried in a TL value.
const IS_VECTOR = 1,
  OPTIONAL = 2,
  BARE = 4,
  FLAGS_WORD = 8,
  VECTOR_MARKER = 16;
type Field = {
  name: string;
  type: string;
  bits: number;
  flagIndex: number;
  mask: number;
  known: number;
};
type Definition = {
  name: string;
  id: number;
  result: string;
  method: boolean;
  fields: Field[];
  optional: Field[];
  allowed: Set<string>;
};
const byName = new Map<string, Definition>(),
  byId = new Map<number, Definition>();
const utf8 = new TextDecoder('utf-8', { fatal: true });
for (const [
  nameIndex,
  id,
  resultIndex,
  method,
  compact = [],
] of schema.definitions) {
  const fields = compact.map(
    ([name, type, bits, flagIndex = 0, flagBit = 0]) => ({
      name: schema.strings[name],
      type: type < 0 ? '#' : schema.strings[type],
      bits,
      flagIndex,
      mask: 1 << flagBit,
      known: 0,
    }),
  );
  const optional = fields.filter((field) => field.bits & OPTIONAL);
  for (const field of optional) fields[field.flagIndex].known |= field.mask;
  const definition = {
    name: schema.strings[nameIndex],
    id,
    result: schema.strings[resultIndex],
    method,
    fields,
    optional,
    allowed: new Set(['_', ...fields.map((field) => field.name)]),
  };
  if (byName.has(definition.name) || byId.has(id))
    throw protocolError('Duplicate TL schema definition');
  byName.set(definition.name, definition);
  byId.set(id, definition);
}
export const requestDefinition = (name: string) => {
  const definition = byName.get(name);
  if (!definition?.method)
    throw protocolError('RPC is not in the local allowlist');
  return definition;
};
export const definitionFor = (name: string) => byName.get(name);
export const definitionById = (id: number) => byId.get(id);

export type DecodeBudget = { nodes: number; inflated: number };
type Reader = { data: Buffer; offset: number; budget: DecodeBudget };
type Writer = {
  data: Buffer;
  length: number;
  flushed: number;
  parts?: Buffer[];
  nodes: number;
};

// Constructor names and fields are validated against the pinned schema.
export type TLObject = { _: string; [field: string]: unknown };
type TLValue =
  | number
  | bigint
  | string
  | boolean
  | Buffer
  | TLObject
  | TLValue[];

export function createReader(
  data: Buffer,
  budget: DecodeBudget = { nodes: 0, inflated: 0 },
): Reader {
  if (!Buffer.isBuffer(data) || data.length > MAX_BYTES)
    throw protocolError('TL buffer exceeds limit');
  return { data, offset: 0, budget };
}

export const remaining = (reader: Reader) => reader.data.length - reader.offset;

function advance(reader: Reader, length: number) {
  if (!Number.isSafeInteger(length) || length < 0 || length > remaining(reader))
    throw protocolError('Truncated TL value');
  const offset = reader.offset;
  reader.offset += length;
  return offset;
}

export function take(reader: Reader, length: number) {
  const offset = advance(reader, length);
  return reader.data.subarray(offset, offset + length);
}

export const readUint = (reader: Reader) =>
  reader.data.readUInt32LE(advance(reader, 4));
export const readInt = (reader: Reader) =>
  reader.data.readInt32LE(advance(reader, 4));
export const readLong = (reader: Reader) =>
  reader.data.readBigInt64LE(advance(reader, 8));

function readByteView(reader: Reader) {
  const marker = reader.data[advance(reader, 1)];
  if (marker === 255) throw protocolError('Invalid TL bytes marker');
  const length =
    marker === 254 ? reader.data.readUIntLE(advance(reader, 3), 3) : marker;
  if (length > MAX_BYTES || (marker === 254 && length < 254))
    throw protocolError('Invalid TL bytes length');
  const value = take(reader, length);
  const padding = -(length + (marker === 254 ? 4 : 1)) & 3;
  const start = advance(reader, padding);
  for (let i = start; i < reader.offset; i++) {
    if (reader.data[i] !== 0) throw protocolError('Nonzero TL padding');
  }
  return value;
}

export const readBytes = (reader: Reader) => Buffer.from(readByteView(reader));

export function finish(reader: Reader) {
  if (remaining(reader)) throw protocolError('Trailing TL bytes');
}

export function readValue(
  reader: Reader,
  type = 'Object',
  bare = false,
  depth = 0,
): TLValue {
  if (depth > MAX_DEPTH || ++reader.budget.nodes > MAX_NODES)
    throw protocolError('TL complexity limit exceeded');
  switch (type) {
    case 'int':
      return readInt(reader);
    case 'long':
      return readLong(reader);
    case 'int128':
      return Buffer.from(take(reader, 16));
    case 'int256':
      return Buffer.from(take(reader, 32));
    case 'double': {
      const value = reader.data.readDoubleLE(advance(reader, 8));
      if (!Number.isFinite(value)) throw protocolError('Nonfinite TL number');
      return value;
    }
    case 'bytes':
      return readBytes(reader);
    case 'string': {
      try {
        return utf8.decode(readByteView(reader));
      } catch {
        throw protocolError('Invalid UTF-8 in TL string');
      }
    }
    case 'true':
      return true;
    case 'Bool': {
      const id = readUint(reader);
      if (id !== TRUE && id !== FALSE) throw protocolError('Invalid TL Bool');
      return id === TRUE;
    }
  }
  const vector = /^Vector<([^<>]+)>$/.exec(type);
  if (vector) return readVector(reader, vector[1], true, false, depth + 1);
  let definition;
  if (bare) {
    definition = byName.get(type);
  } else {
    const id = readUint(reader);
    if (id === GZIP) {
      if (depth > 12) throw protocolError('Nested gzip limit exceeded');
      let inflated;
      try {
        inflated = gunzipSync(readByteView(reader), {
          maxOutputLength: MAX_BYTES - reader.budget.inflated,
        });
      } catch {
        throw protocolError('Invalid or oversized compressed response');
      }
      reader.budget.inflated += inflated.length;
      const inner = createReader(inflated, reader.budget);
      const value = readValue(inner, type, false, depth + 1);
      finish(inner);
      return value;
    }
    if (type === 'Object' && (id === TRUE || id === FALSE)) return id === TRUE;
    definition = byId.get(id);
  }
  if (
    !definition ||
    definition.method ||
    (type !== 'Object' && type !== 'X' && definition.result !== type)
  )
    throw protocolError('Unknown or mismatched TL constructor');
  const value: TLObject = Object.create(null);
  value._ = definition.name;
  for (const field of definition.fields) {
    if (field.bits & FLAGS_WORD) {
      const flags = readUint(reader);
      if (flags & ~field.known)
        throw protocolError(
          'Unsupported TL flag bits; refusing to silently discard' +
            ' unknown state',
        );
      value[field.name] = flags;
      continue;
    }
    if (
      field.bits & OPTIONAL &&
      !((value[definition.fields[field.flagIndex].name] as number) & field.mask)
    ) {
      if (field.type === 'true') value[field.name] = false;
      continue;
    }
    const bareField = Boolean(field.bits & BARE);
    value[field.name] =
      field.bits & IS_VECTOR
        ? readVector(
            reader,
            field.type,
            Boolean(field.bits & VECTOR_MARKER),
            bareField,
            depth + 1,
          )
        : readValue(reader, field.type, bareField, depth + 1);
  }
  return value;
}

function readVector(
  reader: Reader,
  type: string,
  marker: boolean,
  bare: boolean,
  depth: number,
): TLValue[] {
  if (marker && readUint(reader) !== VECTOR)
    throw protocolError('Invalid TL vector marker');
  const count = readInt(reader);
  if (count < 0 || count > MAX_ITEMS || count > remaining(reader) + 1)
    throw protocolError('Invalid TL vector length');
  const values = [];
  for (let i = 0; i < count; i++)
    values.push(readValue(reader, type, bare, depth + 1));
  return values;
}

const createWriter = (): Writer => ({
  data: Buffer.alloc(128),
  length: 0,
  flushed: 0,
  parts: undefined,
  nodes: 0,
});

function reserve(writer: Writer, length: number) {
  const start = writer.length,
    end = start + length;
  if (writer.flushed + end > MAX_BYTES)
    throw protocolError('Encoded TL message exceeds limit');
  if (end > writer.data.length) {
    const data = Buffer.alloc(
      Math.min(MAX_BYTES, Math.max(end, writer.data.length * 2)),
    );
    data.set(writer.data.subarray(0, start));
    writer.data = data;
  }
  writer.length = end;
  return start;
}

function writeUint(writer: Writer, value: number) {
  const start = reserve(writer, 4);
  writer.data.writeUInt32LE(value >>> 0, start);
}

function writeInt(writer: Writer, value: unknown) {
  if (
    typeof value !== 'number' ||
    !Number.isInteger(value) ||
    value < -2_147_483_648 ||
    value > 2_147_483_647
  )
    throw protocolError('Expected a signed TL int');
  const start = reserve(writer, 4);
  writer.data.writeInt32LE(value, start);
}

function writeBytes(writer: Writer, value: unknown) {
  const data = typeof value === 'string' ? Buffer.from(value, 'utf8') : value;
  if (!Buffer.isBuffer(data) || data.length > MAX_BYTES)
    throw protocolError('Invalid TL bytes');
  const header = data.length < 254 ? 1 : 4;
  const length = header + data.length;
  const padding = -length & 3;
  // Keep large blobs separate to avoid growing or copying them with the
  // surrounding fields. Buffer.concat copies them once at the end.
  const large = data.length >= 16 * 1024;
  if (writer.flushed + writer.length + length + padding > MAX_BYTES)
    throw protocolError('Encoded TL message exceeds limit');
  const start = reserve(writer, large ? header : length + padding);
  if (header === 1) writer.data[start] = data.length;
  else {
    writer.data[start] = 254;
    writer.data.writeUIntLE(data.length, start + 1, 3);
  }
  if (large) {
    (writer.parts ??= []).push(writer.data.subarray(0, writer.length), data);
    writer.flushed += writer.length + data.length;
    writer.data = Buffer.alloc(128);
    writer.length = padding;
  } else {
    writer.data.set(data, start + header);
    if (padding) writer.data.fill(0, start + length, writer.length);
  }
}

function writeValue(
  writer: Writer,
  value: unknown,
  type: string,
  bare = false,
  depth = 0,
) {
  if (depth > MAX_DEPTH || ++writer.nodes > MAX_NODES)
    throw protocolError('TL encoding complexity limit exceeded');
  switch (type) {
    case 'int':
      return writeInt(writer, value);
    case 'long': {
      if (
        typeof value !== 'bigint' ||
        value < -(1n << 63n) ||
        value >= 1n << 63n
      )
        throw protocolError('Expected signed bigint for TL long');
      const start = reserve(writer, 8);
      writer.data.writeBigInt64LE(value, start);
      return;
    }
    case 'int128':
    case 'int256': {
      if (
        !Buffer.isBuffer(value) ||
        value.length !== (type === 'int128' ? 16 : 32)
      )
        throw protocolError('Invalid fixed-size TL integer');
      const start = reserve(writer, value.length);
      writer.data.set(value, start);
      return;
    }
    case 'double': {
      if (typeof value !== 'number' || !Number.isFinite(value))
        throw protocolError('Invalid TL double');
      const start = reserve(writer, 8);
      writer.data.writeDoubleLE(value, start);
      return;
    }
    case 'string':
      if (typeof value !== 'string') throw protocolError('Expected TL string');
      return writeBytes(writer, value);
    case 'bytes':
      if (!Buffer.isBuffer(value)) throw protocolError('Expected TL bytes');
      return writeBytes(writer, value);
    case 'true':
      if (value !== true) throw protocolError('Expected flag true');
      return;
    case 'Bool':
      if (typeof value !== 'boolean')
        throw protocolError('Expected TL boolean');
      return writeUint(writer, value ? TRUE : FALSE);
  }
  const vector = /^Vector<([^<>]+)>$/.exec(type);
  if (vector)
    return writeVector(writer, value, vector[1], true, false, depth + 1);
  const object = value as TLObject | null | undefined;
  const definition = object && byName.get(object._);
  if (
    !definition ||
    (type !== 'Object' && type !== 'X' && definition.result !== type)
  )
    throw protocolError('Invalid object for TL field');
  if (bare && definition.name !== type)
    throw protocolError('Mismatched bare TL constructor');
  for (const name of Object.keys(object)) {
    if (!definition.allowed.has(name))
      throw protocolError(
        'Unknown TL field; refusing to silently ignore a parameter',
      );
  }
  if (!bare) writeUint(writer, definition.id);
  const flags: number[] = [];
  for (const field of definition.optional) {
    const item = object[field.name];
    if (
      field.type === 'true'
        ? item === true
        : item !== undefined && item !== null
    )
      flags[field.flagIndex] |= field.mask;
  }
  for (let index = 0; index < definition.fields.length; index++) {
    const field = definition.fields[index];
    if (field.bits & FLAGS_WORD) {
      writeUint(writer, flags[index] ?? 0);
      continue;
    }
    const optional = field.bits & OPTIONAL;
    if (optional && !(flags[field.flagIndex] & field.mask)) continue;
    const item = object[field.name];
    if (optional && field.type === 'true' && item !== true) continue;
    if (item === undefined || item === null)
      throw protocolError(
        `Missing required TL field ${definition.name}.${field.name}`,
      );
    const bareField = Boolean(field.bits & BARE);
    if (field.bits & IS_VECTOR)
      writeVector(
        writer,
        item,
        field.type,
        Boolean(field.bits & VECTOR_MARKER),
        bareField,
        depth + 1,
      );
    else writeValue(writer, item, field.type, bareField, depth + 1);
  }
}

function writeVector(
  writer: Writer,
  values: unknown,
  type: string,
  marker: boolean,
  bare: boolean,
  depth: number,
) {
  if (!Array.isArray(values) || values.length > MAX_ITEMS)
    throw protocolError('Invalid TL vector');
  if (marker) writeUint(writer, VECTOR);
  writeInt(writer, values.length);
  for (const value of values) writeValue(writer, value, type, bare, depth + 1);
}

function writtenBytes(writer: Writer) {
  if (writer.parts) {
    if (writer.length)
      writer.parts.push(writer.data.subarray(0, writer.length));
    return Buffer.concat(writer.parts, writer.flushed + writer.length);
  }
  return writer.data.subarray(0, writer.length);
}

export function encode(value: unknown, type = 'Object') {
  const writer = createWriter();
  writeValue(writer, value, type);
  return writtenBytes(writer);
}
export function decode<T = TLValue>(
  bytes: Buffer,
  type = 'Object',
  budget?: DecodeBudget,
): T {
  const reader = createReader(bytes, budget);
  const value = readValue(reader, type);
  finish(reader);
  return value as T;
}
export function tlBytes(value: unknown) {
  const writer = createWriter();
  writeBytes(writer, value);
  return writtenBytes(writer);
}

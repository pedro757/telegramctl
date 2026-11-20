import { gunzipSync } from 'node:zlib';
import {
  encode,
  decode,
  createReader,
  take,
  readUint,
  readInt,
  readLong,
  readBytes,
  remaining,
  finish,
  requestDefinition,
  definitionById,
  definitionFor,
  MAX_BYTES,
  LAYER,
  type DecodeBudget,
} from './tl.ts';
import {
  createTcpTransport,
  DC_ADDRESSES,
  authenticateKey,
  encryptPacket,
  decryptPacket,
  type Transport,
  type Packet,
} from './wire.ts';
import { randomBytes, sha256, equal } from './crypto.ts';
import {
  now,
  epochSeconds,
  securityError,
  protocolError,
  rpcError,
  isRpcError,
  ambiguousMutationError,
  type RpcError,
} from './common.ts';

const RPC_RESULT = 0xf35c6d01,
  CONTAINER = 0x73f1f8dc,
  GZIP = 0x3072cfa1,
  RPC_ERROR = 0x2144ca19;
const MAX_TRACKED_IDS = 4096;
const INTERNAL_REQUESTS = new Set([
  'ReqPqMulti',
  'ReqDHParams',
  'SetClientDHParams',
  'InvokeWithLayer',
  'InitConnection',
  'InvokeWithoutUpdates',
]);
const SERVICES = new Set([
  'NewSessionCreated',
  'BadServerSalt',
  'BadMsgNotification',
  'MsgsAck',
  'MsgDetailedInfo',
  'MsgNewDetailedInfo',
  'MsgsStateReq',
  'MsgsStateInfo',
  'MsgsAllInfo',
  'MsgResendReq',
  'Pong',
]);
const MUTATIONS = new Set([
  'DestroyAuthKey',
  'auth.SendCode',
  'auth.SignIn',
  'auth.CheckPassword',
  'auth.LogOut',
  'auth.ExportAuthorization',
  'auth.ImportAuthorization',
  'messages.SendMessage',
  'messages.SendMedia',
  'messages.DeleteMessages',
  'channels.DeleteMessages',
  'upload.SaveFilePart',
  'upload.SaveBigFilePart',
  'account.UpdateNotifySettings',
  'messages.DeleteChatUser',
  'channels.EditBanned',
  'channels.EditAdmin',
  'messages.EditChatAdmin',
  'messages.EditChatCreator',
  'messages.UpdateDialogFilter',
]);

export type ConnectionSession = {
  apiId: number;
  dcId?: number;
  timeOffset?: number;
  salt?: bigint;
  authKey?: Buffer;
};
export type RpcOptions = { mutation?: boolean };
export type RpcClient = {
  invoke(name: string, args?: object, options?: RpcOptions): Promise<unknown>;
};
type PendingRpc = {
  ids: Set<bigint>;
  requestSalts: Set<bigint>;
  acks: Set<bigint>;
  resultType: string;
  destroyKey: boolean;
  routed: number;
  budget: DecodeBudget;
  activeId?: bigint;
  activeSalt?: bigint;
  activeSequence?: number;
  done?: boolean;
  retry?: boolean;
  error?: RpcError;
  result?: unknown;
};
type RejectedMessage = {
  badMsgId: bigint;
  badMsgSeqno: number;
  errorCode: number;
};
type ServiceMessage = RejectedMessage & {
  _: string;
  firstMsgId: bigint;
  serverSalt: bigint;
  newServerSalt: bigint;
  answerMsgId: bigint;
  msgIds: bigint[];
};

// Server IDs may arrive out of order. A bounded min-heap lets us evict the
// lowest ID (not the first arrival) without scanning the replay cache.
function retainReceivedId(heap: bigint[], id: bigint) {
  if (heap.length < MAX_TRACKED_IDS) {
    let index = heap.length;
    while (index > 0) {
      const parent = (index - 1) >> 1;
      if (heap[parent] <= id) break;
      heap[index] = heap[parent];
      index = parent;
    }
    heap[index] = id;
    return undefined;
  }
  const oldest = heap[0];
  if (id < oldest) return id;
  let index = 0;
  for (let child = 1; child < heap.length; child = index * 2 + 1) {
    const right = child + 1;
    if (right < heap.length && heap[right] < heap[child]) child = right;
    if (heap[child] >= id) break;
    heap[index] = heap[child];
    index = child;
  }
  heap[index] = id;
  return oldest;
}

function messageAge(id: bigint, timeOffset: number) {
  const seconds = Number(id >> 32n) + Number(id & 0xffffffffn) / 2 ** 32;
  return epochSeconds() + timeOffset - seconds;
}

export function createRpcClient(
  session: ConnectionSession,
  {
    transportFactory = createTcpTransport,
    ephemeral = false,
  }: {
    transportFactory?: (dcId: number) => Transport;
    ephemeral?: boolean;
  } = {},
) {
  const { apiId } = session,
    dcId = session.dcId ?? 2;
  if (!Number.isInteger(apiId) || apiId <= 0 || apiId > 2_147_483_647)
    throw securityError('Invalid Telegram API ID');
  if (ephemeral && session.authKey)
    throw securityError('An ephemeral client must generate its own key');
  let timeOffset = session.timeOffset ?? 0,
    salt = session.salt ?? 0n;
  let key: Buffer | undefined = session.authKey
    ? Buffer.from(session.authKey)
    : undefined;
  if (key && key.length !== 256)
    throw securityError('Invalid session authentication key');
  if (
    !Number.isFinite(timeOffset) ||
    Math.abs(timeOffset) > 86400 ||
    typeof salt !== 'bigint'
  )
    throw securityError('Invalid session state');
  const sessionId = randomBytes(8),
    transport = transportFactory(dcId);
  const received = new Map<bigint, Buffer>(),
    receivedIds: bigint[] = [],
    sent = new Set<bigint>(),
    salts = new Set<bigint>();
  if (salt) salts.add(salt);
  let sequence = 0,
    lastId = 0n,
    receivedFloor = 0n;
  let busy = false,
    initialized = false,
    opened = false,
    closed = false;

  function nextId() {
    const nanos = now().epochNanoseconds + BigInt(Math.trunc(timeOffset * 1e9));
    let id = ((nanos << 32n) / 1_000_000_000n) & ~3n;
    if (id <= lastId) id = lastId + 4n;
    lastId = id;
    return id;
  }

  async function open() {
    if (closed) throw protocolError('Closed RPC clients cannot be reused');
    if (opened) return;
    await transport.connect();
    try {
      if (!key) {
        const result = await authenticateKey(transport, nextId, dcId);
        key = result.authKey;
        timeOffset = result.timeOffset;
        setSalt(result.salt);
        lastId = 0n; // Plain-handshake IDs used the pre-synchronization clock.
      }
      opened = true;
    } catch (error) {
      close();
      throw error;
    }
  }

  function exportSession() {
    if (!key) throw securityError('Session is not connected');
    return { dcId, authKey: Buffer.from(key), salt, timeOffset };
  }

  function close() {
    transport.close();
    key?.fill(0);
    key = undefined;
    sessionId.fill(0);
    opened = false;
    closed = true;
  }

  function setSalt(newSalt: bigint) {
    salt = newSalt;
    salts.add(newSalt);
    while (salts.size > 16) salts.delete(salts.values().next().value!);
  }

  async function sendPacket(body: Buffer, contentRelated: boolean) {
    const id = nextId(),
      seqNo = sequence * 2 + (contentRelated ? 1 : 0);
    if (contentRelated) sequence++;
    sent.add(id);
    if (sent.size > MAX_TRACKED_IDS) sent.delete(sent.values().next().value!);
    await transport.send(
      encryptPacket({ authKey: key!, sessionId, salt, msgId: id, seqNo, body }),
    );
    return id;
  }

  function observe(id: bigint, body: Buffer, clockCorrection = false) {
    const age = messageAge(id, timeOffset);
    if (
      !(id & 1n) ||
      (!clockCorrection && (age > 300 || age < -30)) ||
      id <= receivedFloor
    )
      throw securityError(
        'Rejected stale, future, or invalid server message ID',
      );
    const digest = sha256(body),
      prior = received.get(id);
    if (prior) {
      if (!equal(prior, digest))
        throw securityError(
          'Same server message ID used for different content',
        );
      return false;
    }
    const oldest = retainReceivedId(receivedIds, id);
    if (oldest !== undefined) {
      received.delete(oldest);
      receivedFloor = oldest;
    }
    if (oldest !== id) received.set(id, digest);
    return true;
  }

  function clockOffset(
    service: RejectedMessage,
    msgId: bigint,
    pending: PendingRpc,
  ) {
    if (
      service.badMsgId !== pending.activeId ||
      service.badMsgSeqno !== pending.activeSequence
    )
      throw securityError('Uncorrelated bad-message clock notification');
    if (service.errorCode !== 16 && service.errorCode !== 17)
      throw protocolError(
        'Telegram rejected the message sequence; reconnect before retrying',
      );
    const serverSeconds = Number(msgId >> 32n),
      requestSeconds = Number(service.badMsgId >> 32n);
    const offset = serverSeconds - epochSeconds();
    if (
      Math.abs(offset) > 86400 ||
      (service.errorCode === 16
        ? requestSeconds >= serverSeconds
        : requestSeconds <= serverSeconds)
    )
      throw securityError('Invalid server clock correction');
    return offset;
  }

  function recoverClock(packet: Packet, pending: PendingRpc) {
    const age = messageAge(packet.msgId, timeOffset);
    if (age <= 300 && age >= -30) return false;
    // Only a standalone authenticated clock rejection can bypass freshness.
    // Containers/compressed/ordinary results still require the normal window.
    if (
      packet.body.readUInt32LE() !== definitionFor('BadMsgNotification')!.id ||
      (!salts.has(packet.salt) && packet.salt !== pending.activeSalt)
    )
      throw securityError(
        'Rejected stale/future packet without a correlated clock correction',
      );
    const service = decode<RejectedMessage>(
      packet.body,
      'Object',
      pending.budget,
    );
    const offset = clockOffset(service, packet.msgId, pending);
    if (!observe(packet.msgId, packet.body, true))
      throw securityError('Replayed clock correction');
    timeOffset = offset;
    lastId = 0n;
    return true;
  }

  function inflate(
    reader: ReturnType<typeof createReader>,
    pending: PendingRpc,
  ) {
    let data;
    try {
      data = gunzipSync(readBytes(reader), {
        maxOutputLength: MAX_BYTES - pending.budget.inflated,
      });
    } catch {
      throw protocolError('Invalid or oversized compressed Telegram packet');
    }
    finish(reader);
    pending.budget.inflated += data.length;
    return data;
  }

  function rpcPayload(bytes: Buffer, pending: PendingRpc, depth: number): void {
    if (depth > 12)
      throw protocolError('Compressed RPC nesting limit exceeded');
    if (pending.done || pending.error)
      throw securityError('Multiple results for one pending RPC');
    const reader = createReader(bytes, pending.budget),
      id = readUint(reader);
    if (id === GZIP)
      return rpcPayload(inflate(reader, pending), pending, depth + 1);
    if (id === RPC_ERROR) {
      const error = decode<{ errorCode: number; errorMessage: string }>(
        bytes,
        'RpcError',
        pending.budget,
      );
      pending.error = rpcError(error.errorCode, error.errorMessage);
      return;
    }
    pending.result = decode(bytes, pending.resultType, pending.budget);
    pending.done = true;
  }

  async function route(
    body: Buffer,
    msgId: bigint,
    seqNo: number,
    pending: PendingRpc,
    depth = 0,
    alreadyObserved = false,
  ) {
    if (depth > 12 || ++pending.routed > 4096)
      throw protocolError('Message nesting/count limit exceeded');
    if (!alreadyObserved && !observe(msgId, body)) {
      if (seqNo & 1) pending.acks.add(msgId);
      return;
    }
    if (seqNo & 1) pending.acks.add(msgId);
    const reader = createReader(body, pending.budget),
      id = readUint(reader);
    if (id === CONTAINER) {
      const count = readInt(reader);
      if (count < 0 || count > 1024 || count * 20 > remaining(reader))
        throw protocolError('Invalid message container count');
      for (let index = 0; index < count; index++) {
        const innerId = readLong(reader),
          innerSeq = readInt(reader),
          length = readInt(reader);
        if (innerId >= msgId || innerSeq < 0 || length < 4 || length % 4)
          throw securityError('Invalid inner message header');
        await route(
          take(reader, length),
          innerId,
          innerSeq,
          pending,
          depth + 1,
        );
      }
      finish(reader);
      return;
    }
    if (id === GZIP)
      return route(
        inflate(reader, pending),
        msgId,
        seqNo,
        pending,
        depth + 1,
        true,
      );
    if (id === RPC_RESULT) {
      const requestId = readLong(reader);
      if (pending.ids.has(requestId))
        rpcPayload(take(reader, remaining(reader)), pending, 0);
      return;
    }
    const definition = definitionById(id);
    if (!definition || definition.method)
      throw protocolError('Unexpected message constructor');
    if (pending.destroyKey && definition.result === 'DestroyAuthKeyRes') {
      rpcPayload(body, pending, depth);
      return;
    }
    // This is a pull-only client. invokeWithoutUpdates suppresses unrelated
    // updates; any that still arrive are authenticated and acknowledged but
    // never executed, cached, or recursively interpreted as instructions.
    if (definition.result === 'Updates' || definition.result === 'Update')
      return;
    if (!SERVICES.has(definition.name))
      throw protocolError('Unsupported service message');
    const service = decode<ServiceMessage>(body, 'Object', pending.budget);
    if (service._ === 'NewSessionCreated') {
      if (!sent.has(service.firstMsgId))
        throw securityError(
          'New-session response does not reference a sent message',
        );
      setSalt(service.serverSalt);
    } else if (service._ === 'BadServerSalt') {
      if (
        service.badMsgId !== pending.activeId ||
        service.badMsgSeqno !== pending.activeSequence ||
        service.errorCode !== 48
      )
        throw securityError('Uncorrelated bad-server-salt message');
      setSalt(service.newServerSalt);
      pending.retry = true;
    } else if (service._ === 'BadMsgNotification') {
      const offset = clockOffset(service, msgId, pending);
      timeOffset = offset;
      lastId = 0n;
      pending.retry = true;
    } else if (
      service._ === 'MsgDetailedInfo' ||
      service._ === 'MsgNewDetailedInfo'
    ) {
      pending.acks.add(service.answerMsgId);
    } else if (service._ === 'MsgsStateReq' || service._ === 'MsgResendReq') {
      // No automatic replay: report that unknown message IDs are not present.
      await sendPacket(
        encode({
          _: 'MsgsStateInfo',
          reqMsgId: msgId,
          info: Buffer.alloc(service.msgIds.length, 1),
        }),
        false,
      );
    }
  }

  async function invoke<T = unknown>(
    name: string,
    args: object = {},
    { mutation = false }: RpcOptions = {},
  ): Promise<T> {
    const definition = requestDefinition(name);
    if (MUTATIONS.has(name) && !mutation)
      throw protocolError(
        'A mutation must be explicitly classified as such; it is' +
          ' never treated as a retryable read',
      );
    if (!opened || !key) throw protocolError('RPC client is not connected');
    if (busy)
      throw protocolError('Concurrent RPCs are deliberately unsupported');
    if (INTERNAL_REQUESTS.has(name))
      throw protocolError('Protocol wrappers are internal only');
    const destroyKey = name === 'DestroyAuthKey';
    if (destroyKey && !ephemeral)
      throw securityError('Refusing to destroy the saved session key');
    if (name === 'auth.ImportAuthorization' && !ephemeral)
      throw securityError('Authorization import requires an ephemeral client');
    busy = true;
    let submitted = false,
      lastExplicitRejection = false;
    let body: Buffer | undefined;
    try {
      const request = { ...args, _: name };
      const query = { _: 'InvokeWithoutUpdates', query: request };
      const wrapped = initialized
        ? query
        : {
            _: 'InvokeWithLayer',
            layer: LAYER,
            query: {
              _: 'InitConnection',
              apiId,
              deviceModel: 'telegram-cli',
              systemVersion: `Node.js ${process.version} ${process.platform}`,
              appVersion: '0.1.0',
              systemLangCode: 'en',
              langPack: '',
              langCode: 'en',
              query,
            },
          };
      body = encode(destroyKey ? request : wrapped);
      const resultType = definition.result;
      const deadline = performance.now() + (destroyKey ? 10_000 : 60_000);
      const pending: PendingRpc = {
        ids: new Set(),
        requestSalts: new Set(),
        resultType,
        destroyKey,
        acks: new Set(),
        routed: 0,
        budget: { nodes: 0, inflated: 0 },
      };
      for (let attempt = 0; attempt < 3; attempt++) {
        pending.retry = false;
        lastExplicitRejection = false;
        submitted = true;
        pending.activeSalt = salt;
        pending.activeSequence = sequence * 2 + 1;
        pending.requestSalts.add(salt);
        const id = await sendPacket(body, true);
        pending.ids.add(id);
        pending.activeId = id;
        while (!pending.done && !pending.error && !pending.retry) {
          const remaining = deadline - performance.now();
          if (remaining <= 0) throw protocolError('RPC deadline exceeded');
          const packet = decryptPacket(
            await transport.receive(Math.min(30_000, remaining)),
            key,
            sessionId,
          );
          const hadSalt = salts.has(packet.salt);
          const clockRecovered = recoverClock(packet, pending);
          await route(
            packet.body,
            packet.msgId,
            packet.seqNo,
            pending,
            0,
            clockRecovered,
          );
          lastExplicitRejection = Boolean(pending.retry);
          // Imported sessions start with unknown salt=0. A correlated explicit
          // rejection may be sent under that requested salt while carrying the
          // corrected salt. It must not make arbitrary RPC salts acceptable.
          const rejectionSalt =
            pending.retry && pending.requestSalts.has(packet.salt);
          if (!hadSalt && !salts.has(packet.salt) && !rejectionSalt)
            throw securityError('Unrecognized Telegram server salt');
          if (pending.acks.size && !(destroyKey && pending.done)) {
            try {
              await sendPacket(
                encode({ _: 'MsgsAck', msgIds: [...pending.acks] }),
                false,
              );
            } catch (error) {
              if (!pending.done && !pending.error) throw error;
            }
            pending.acks.clear();
          }
        }
        if (pending.error) throw pending.error;
        if (pending.done) {
          initialized = true;
          return pending.result as T;
        }
      }
      throw protocolError('Server rejection retry limit exceeded');
    } catch (error) {
      if (mutation && submitted && !lastExplicitRejection && !isRpcError(error))
        throw ambiguousMutationError();
      throw error;
    } finally {
      if (name === 'auth.ImportAuthorization') body?.fill(0);
      busy = false;
    }
  }

  return { open, invoke, exportSession, close };
}

async function removeMediaKey(rpc: RpcClient) {
  const result = (await rpc.invoke(
    'DestroyAuthKey',
    {},
    { mutation: true },
  )) as { _: string };
  if (result._ !== 'DestroyAuthKeyOk' && result._ !== 'DestroyAuthKeyNone')
    throw protocolError('Media key destruction was not confirmed');
}

export function createMediaRpc(
  main: RpcClient,
  session: ConnectionSession,
  makeClient: typeof createRpcClient,
  warning: (message: string) => void,
) {
  return async <T>(
    dcId: number,
    accountId: bigint,
    transfer: (rpc: RpcClient) => Promise<T>,
  ) => {
    if (!Number.isInteger(dcId) || !Object.hasOwn(DC_ADDRESSES, dcId))
      throw securityError('Media is hosted on an unsupported data center');
    if (dcId === session.dcId) return transfer(main);

    const remote = makeClient(
      { apiId: session.apiId, dcId },
      {
        ephemeral: true,
      },
    );
    let opened = false;
    try {
      await remote.open();
      opened = true;
      const result = (await main.invoke(
        'auth.ExportAuthorization',
        { dcId },
        { mutation: true },
      )) as { _: string; id: bigint; bytes: Buffer };
      if (!Buffer.isBuffer(result?.bytes))
        throw protocolError('Invalid data-center authorization transfer');
      try {
        if (
          result._ !== 'auth.ExportedAuthorization' ||
          typeof result.id !== 'bigint' ||
          !result.bytes.length ||
          result.bytes.length > 65_536
        )
          throw protocolError('Invalid data-center authorization transfer');
        const imported = await remote.invoke<{
          _: string;
          user?: { _: string; id: bigint; bot?: boolean };
          futureAuthToken?: Buffer;
        }>(
          'auth.ImportAuthorization',
          { id: result.id, bytes: result.bytes },
          { mutation: true },
        );
        imported?.futureAuthToken?.fill(0);
        if (
          imported?._ !== 'auth.Authorization' ||
          imported.user?._ !== 'User' ||
          imported.user.id !== accountId ||
          imported.user.bot
        )
          throw securityError('Media data center authorized a different user');
      } finally {
        result.bytes.fill(0);
      }
      return await transfer(remote);
    } finally {
      try {
        if (opened) await removeMediaKey(remote);
      } catch {
        warning(
          'Could not confirm temporary media authorization removal.' +
            ' Check Telegram Settings > Devices for an extra session.',
        );
      } finally {
        remote.close();
      }
    }
  };
}

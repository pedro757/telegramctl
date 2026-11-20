import {
  epochSeconds,
  isoSeconds,
  securityError,
  protocolError,
  approvalError,
  ambiguousMutationError,
  isAmbiguousMutationError,
  isRpcError,
  safeJson,
} from './common.ts';
import {
  randomLong,
  sha256,
  passwordCheck,
  type PasswordParameters,
} from './crypto.ts';
import {
  downloadTemporary,
  type AuditRecord,
  type AuditStatus,
  type openAttachment,
} from './files.ts';
import { join } from 'node:path';
import type { createMediaRpc, RpcClient, RpcOptions } from './rpc.ts';
import type { TLObject } from './tl.ts';

type PeerKind = 'user' | 'chat' | 'channel';
export type Peer = {
  _: string;
  id?: bigint;
  userId?: bigint;
  chatId?: bigint;
  channelId?: bigint;
};
export type Entity = Peer & {
  title?: string;
  firstName?: string;
  lastName?: string;
  username?: string;
  phone?: string;
  min?: boolean;
  deleted?: boolean;
  self?: boolean;
  bot?: boolean;
  noforwards?: boolean;
  megagroup?: boolean;
  creator?: boolean;
  adminRights?: object;
  mutualContact?: boolean;
  accessHash?: bigint;
  participantsCount?: number;
};
type EntityCache = Map<string, Entity>;
type EntityResult = {
  users?: Entity[];
  chats?: Entity[];
  user?: Entity;
};
type Dialog = {
  _: string;
  peer: Peer;
  topMessage: number;
  unreadCount?: number;
  unreadMark?: boolean;
  notifySettings?: { muteUntil?: number };
};
type FileReference = {
  id: bigint;
  accessHash: bigint;
  fileReference: Buffer;
  dcId: number;
};
type PhotoSize = {
  _: string;
  type: string;
  w?: number;
  h?: number;
  size?: number;
  sizes?: number[];
};
type Media = {
  _: string;
  ttlSeconds?: number;
  voice?: boolean;
  photo?: FileReference & { _: string; sizes?: PhotoSize[] };
  document?: Partial<FileReference> & {
    _: string;
    size: bigint;
    mimeType: string;
    attributes?: Array<{
      _: string;
      fileName?: string;
      voice?: boolean;
      roundMessage?: boolean;
    }>;
  };
};
type WireMessage = {
  _: string;
  id: number;
  date?: number;
  peerId?: Peer;
  fromId?: Peer;
  message?: string;
  out?: boolean;
  post?: boolean;
  noforwards?: boolean;
  ttlPeriod?: number;
  replyTo?: { replyToMsgId?: number };
  action?: { _: string };
  media?: Media;
};
type HistoryOptions = {
  limit?: number;
  since?: number;
  until?: number;
  minId?: number;
  includeService?: boolean;
};
type Participant = { _: string; userId?: bigint; peer?: Peer };
type FullChat = {
  fullChat?: {
    about?: string;
    participants?: { _: string; participants: Participant[] };
    participantsCount?: number;
    adminsCount?: number;
    linkedChatId?: bigint;
  };
};
type Participants = { participants: Participant[] };
type SearchPage = { messages: WireMessage[]; nextRate?: number };
type SentUpdate = {
  _: string;
  id?: number;
  randomId?: bigint;
  message?: { id: number; out?: boolean };
};
type SendResult = SentUpdate & { update: SentUpdate; updates?: SentUpdate[] };
type FolderFilter = TLObject & {
  id?: number;
  title?: string | { text: string };
  includePeers?: Peer[];
  pinnedPeers?: Peer[];
  excludePeers?: Peer[];
};
type RpcRequest = [name: string, args: object];

const MAX_ID = (1n << 63n) - 1n;
const PEER_TYPES = new Map<string, PeerKind>([
  ['PeerUser', 'user'],
  ['InputPeerUser', 'user'],
  ['InputPeerUserFromMessage', 'user'],
  ['InputUser', 'user'],
  ['User', 'user'],
  ['UserEmpty', 'user'],
  ['PeerChat', 'chat'],
  ['InputPeerChat', 'chat'],
  ['Chat', 'chat'],
  ['ChatForbidden', 'chat'],
  ['PeerChannel', 'channel'],
  ['InputPeerChannel', 'channel'],
  ['InputPeerChannelFromMessage', 'channel'],
  ['InputChannel', 'channel'],
  ['Channel', 'channel'],
  ['ChannelForbidden', 'channel'],
]);
const CACHEABLE_ENTITIES = new Set([
  'User',
  'UserEmpty',
  'Chat',
  'ChatForbidden',
  'Channel',
  'ChannelForbidden',
]);
const RESTRICTED_ENTITIES = new Set([
  'UserEmpty',
  'ChatForbidden',
  'ChannelForbidden',
]);

export function parsePeerId(identifier: unknown) {
  if (typeof identifier !== 'string')
    throw securityError('Expected a peer identifier');
  const typed = /^(user|chat|channel):([1-9][0-9]{0,18})$/.exec(identifier);
  if (typed) {
    const id = BigInt(typed[2]);
    if (id > MAX_ID) throw securityError('Peer ID exceeds supported range');
    const kind = typed[1] as PeerKind;
    return { kind, id, key: `${kind}:${id}` };
  }
  if (/^-?[0-9]+$/.test(identifier)) {
    if (!/^-?[1-9][0-9]{0,18}$/.test(identifier))
      throw securityError('Invalid numeric peer ID');
    const raw = BigInt(identifier);
    const kind =
      raw > 0n ? 'user' : raw <= -1_000_000_000_000n ? 'channel' : 'chat';
    const id =
      raw > 0n ? raw : kind === 'channel' ? -raw - 1_000_000_000_000n : -raw;
    if (id < 1n || id > MAX_ID) throw securityError('Invalid numeric peer ID');
    return { kind, id, key: `${kind}:${id}` };
  }
  if (/^(user|chat|channel):/.test(identifier))
    throw securityError('Malformed type-qualified peer ID');
  return null;
}
function peerKind(peer: Peer | undefined) {
  if (!peer || typeof peer !== 'object')
    throw protocolError('Invalid Telegram peer');
  const kind = PEER_TYPES.get(peer._);
  if (!kind) throw protocolError('Unsupported or invalid Telegram peer type');
  return kind;
}

function peerId(peer: Peer) {
  const id = peer.userId ?? peer.chatId ?? peer.channelId ?? peer.id;
  if (typeof id !== 'bigint' || id <= 0n || id > MAX_ID)
    throw protocolError('Unsupported or invalid Telegram peer type');
  return id;
}
export const peerKey = (peer: Peer | undefined) =>
  `${peerKind(peer)}:${peerId(peer!)}`;
export const entityTitle = (entity: Entity) =>
  (entity.title ??
    [entity.firstName, entity.lastName].filter(Boolean).join(' ')) ||
  entity.username ||
  'Unknown';

export function rememberEntity(entities: EntityCache, entity?: Entity) {
  if (!entity || !CACHEABLE_ENTITIES.has(entity._)) return;
  const key = peerKey(entity),
    previous = entities.get(key);
  if (!previous || !entity.min || previous.min) entities.set(key, entity);
}

function ingestEntities<T>(entities: EntityCache, result: T): T {
  if (!result || typeof result !== 'object') return result;
  const { users, chats, user } = result as EntityResult;
  for (const entity of users ?? []) rememberEntity(entities, entity);
  for (const entity of chats ?? []) rememberEntity(entities, entity);
  if (user) rememberEntity(entities, user);
  return result;
}

export function inputPeer(entity?: Entity) {
  if (
    !entity ||
    entity.min ||
    entity.deleted ||
    RESTRICTED_ENTITIES.has(entity._)
  )
    throw securityError(
      'Peer is unavailable or only a restricted/minimal entity was returned',
    );
  const kind = peerKind(entity),
    id = peerId(entity);
  if (kind === 'chat') return { _: 'InputPeerChat', chatId: id };
  if (typeof entity.accessHash !== 'bigint') {
    if (entity.self) return { _: 'InputPeerSelf' };
    throw securityError(
      'Missing peer access hash; resolve an explicit @username or' +
        ' an existing dialog',
    );
  }
  return kind === 'user'
    ? { _: 'InputPeerUser', userId: id, accessHash: entity.accessHash }
    : { _: 'InputPeerChannel', channelId: id, accessHash: entity.accessHash };
}

function inputUser(entity: Entity) {
  const kind = peerKind(entity);
  peerId(entity);
  if (kind !== 'user') throw securityError('Target must be a user');
  if (entity.self) return { _: 'InputUserSelf' };
  const input = inputPeer(entity);
  return { _: 'InputUser', userId: input.userId, accessHash: input.accessHash };
}

function inputChannel(entity: Entity) {
  const input = inputPeer(entity);
  if (input._ !== 'InputPeerChannel')
    throw securityError('Target must be a channel or supergroup');
  return {
    _: 'InputChannel',
    channelId: input.channelId,
    accessHash: input.accessHash,
  };
}

export function summarizePeer(entity: Entity, dialog?: Dialog) {
  const kind = peerKind(entity),
    id = `${kind}:${peerId(entity)}`;
  return {
    id,
    title: entityTitle(entity),
    type:
      kind === 'user'
        ? 'user'
        : kind === 'chat'
          ? 'group'
          : entity.megagroup
            ? 'supergroup'
            : 'channel',
    ...(entity.username ? { username: entity.username } : {}),
    ...(dialog
      ? {
          unreadCount: dialog.unreadCount ?? 0,
          unreadMark: Boolean(dialog.unreadMark),
          muted: (dialog.notifySettings?.muteUntil ?? 0) > epochSeconds(),
        }
      : {}),
    isAdmin: Boolean(entity.creator || entity.adminRights),
    isCreator: Boolean(entity.creator),
  };
}

type DialogSummary = ReturnType<typeof summarizePeer> & {
  lastMessage?: string;
  lastMessageDate?: string;
  previewTruncated?: boolean;
};
function exactNameMatch(dialogs: DialogSummary[], identifier: string) {
  const name = identifier.toLowerCase();
  const matches = dialogs.filter(
    (dialog) => dialog.title.toLowerCase() === name,
  );
  if (matches.length !== 1)
    throw securityError(
      matches.length
        ? `Ambiguous chat name; use one of these stable IDs: ${matches
            .slice(0, 30)
            .map((item) => item.id)
            .join(', ')}`
        : 'Chat not found by exact name. List dialogs and use a' +
            ' type-qualified ID or @username.',
    );
  return matches[0].id;
}

export const ADMIN_RIGHTS = Object.freeze([
  'changeInfo',
  'postMessages',
  'editMessages',
  'deleteMessages',
  'banUsers',
  'inviteUsers',
  'pinMessages',
  'addAdmins',
  'anonymous',
  'manageCall',
  'manageTopics',
  'postStories',
  'editStories',
  'deleteStories',
  'manageDirectMessages',
  'manageRanks',
  'manageLinkedPeers',
  'manageWelcomeMessages',
]);
export const FOLDER_CATEGORIES = Object.freeze([
  'contacts',
  'nonContacts',
  'groups',
  'broadcasts',
  'bots',
]);
export function validateMessageText(text: unknown) {
  if (
    typeof text !== 'string' ||
    !text.length ||
    text.length > 4096 ||
    Buffer.byteLength(text) > 16_384 ||
    !text.isWellFormed() ||
    text.includes('\0')
  )
    throw securityError(
      'Message must contain 1–4096 well-formed characters and no NUL',
    );
  return text;
}
const positiveLimit = (value: number, maximum = 10_000) => {
  if (!Number.isInteger(value) || value < 1 || value > maximum)
    throw securityError(`Limit must be from 1 to ${maximum}`);
  return value;
};
function mediaInfo(media?: Media) {
  if (!media || media._ === 'MessageMediaEmpty') return undefined;
  const result: {
    type: string;
    size?: string;
    mimeType?: string;
    fileName?: string;
  } = { type: media._.replace(/^MessageMedia/, '').toLowerCase() };
  if (media.document?._ === 'Document') {
    const document = media.document;
    result.size = document.size.toString();
    result.mimeType = document.mimeType;
    for (const attribute of document.attributes ?? []) {
      if (attribute._ === 'DocumentAttributeFilename')
        result.fileName = attribute.fileName;
      if (attribute._ === 'DocumentAttributeAudio')
        result.type = attribute.voice ? 'voice' : 'audio';
      if (attribute._ === 'DocumentAttributeVideo')
        result.type = attribute.roundMessage ? 'video_note' : 'video';
      if (attribute._ === 'DocumentAttributeSticker') result.type = 'sticker';
      if (attribute._ === 'DocumentAttributeAnimated') result.type = 'gif';
    }
  }
  return result;
}

export const MAX_DOWNLOAD_MIB = 20;
const FILE_CHUNK = 512 * 1024;
const imageTypes = new Map([
  ['image/jpeg', 'jpg'],
  ['image/png', 'png'],
  ['image/gif', 'gif'],
  ['image/webp', 'webp'],
]);
const imageSuffixes = new Map([
  ['jpg', 'jpg'],
  ['jpeg', 'jpg'],
  ['png', 'png'],
  ['gif', 'gif'],
  ['webp', 'webp'],
]);
const audioTypes = new Map([
  ['audio/ogg', 'ogg'],
  ['audio/opus', 'ogg'],
  ['audio/x-opus+ogg', 'ogg'],
  ['application/ogg', 'ogg'],
  ['audio/mpeg', 'mp3'],
  ['audio/mp3', 'mp3'],
  ['audio/mp4', 'm4a'],
  ['audio/m4a', 'm4a'],
  ['audio/x-m4a', 'm4a'],
  ['audio/wav', 'wav'],
  ['audio/wave', 'wav'],
  ['audio/x-wav', 'wav'],
  ['audio/vnd.wave', 'wav'],
  ['audio/flac', 'flac'],
  ['audio/x-flac', 'flac'],
]);
const audioSuffixes = new Map([
  ['ogg', 'ogg'],
  ['oga', 'ogg'],
  ['opus', 'ogg'],
  ['mp3', 'mp3'],
  ['m4a', 'm4a'],
  ['wav', 'wav'],
  ['flac', 'flac'],
]);
const attachmentTypes = new Map([
  ['application/pdf', 'pdf'],
  ['application/zip', 'zip'],
  ['application/gzip', 'gz'],
  ['text/plain', 'txt'],
  ['video/mp4', 'mp4'],
  ['video/ogg', 'ogv'],
  ['video/quicktime', 'mov'],
  ['video/webm', 'webm'],
]);
function imageExtension(bytes: Buffer) {
  if (bytes.subarray(0, 3).equals(Buffer.from([255, 216, 255]))) return 'jpg';
  if (bytes.subarray(0, 8).equals(Buffer.from('89504e470d0a1a0a', 'hex')))
    return 'png';
  const head = bytes.toString('latin1', 0, 6);
  if (head === 'GIF87a' || head === 'GIF89a') return 'gif';
  if (
    bytes.toString('latin1', 0, 4) === 'RIFF' &&
    bytes.toString('latin1', 8, 12) === 'WEBP'
  )
    return 'webp';
  return undefined;
}

function audioExtension(bytes: Buffer) {
  const tag = (start: number, end: number) =>
    bytes.toString('latin1', start, end);
  const head = tag(0, 4);
  if (head === 'OggS' && bytes[4] === 0 && bytes[5] === 2 && bytes[26]) {
    // The first packet follows the page's segment table. Don't accept video
    // or an arbitrary Ogg stream as an audio file.
    const firstPacket = 27 + bytes[26];
    if (
      (bytes[27] >= 8 && tag(firstPacket, firstPacket + 8) === 'OpusHead') ||
      (bytes[27] >= 7 && tag(firstPacket, firstPacket + 7) === '\x01vorbis')
    )
      return 'ogg';
  }
  if (head === 'RIFF' && tag(8, 12) === 'WAVE') return 'wav';
  if (head === 'fLaC') return 'flac';
  if (bytes.length >= 16 && tag(4, 8) === 'ftyp') {
    const boxSize = bytes.readUInt32BE(0);
    if (boxSize >= 16 && boxSize <= bytes.length && boxSize % 4 === 0) {
      const isAudioBrand = (offset: number) => {
        const brand = tag(offset, offset + 4);
        return brand === 'M4A ' || brand === 'M4B ';
      };
      if (isAudioBrand(8)) return 'm4a';
      for (let offset = 16; offset < boxSize; offset += 4)
        if (isAudioBrand(offset)) return 'm4a';
    }
  }
  if (
    bytes.length >= 10 &&
    tag(0, 3) === 'ID3' &&
    bytes[3] >= 2 &&
    bytes[3] <= 4 &&
    bytes[4] !== 255 &&
    bytes.subarray(6, 10).every((value) => value < 128)
  )
    return 'mp3';
  if (
    bytes.length >= 4 &&
    bytes[0] === 255 &&
    (bytes[1] & 0xe6) === 0xe2 &&
    (bytes[1] & 0x18) !== 0x08 &&
    bytes[2] >> 4 !== 15 &&
    (bytes[2] & 0x0c) !== 0x0c
  )
    return 'mp3';
  return undefined;
}

function largestPhoto(photo: { sizes?: PhotoSize[] }) {
  let best: { thumbSize: string; size: number; area: number } | undefined;
  for (const variant of photo.sizes ?? []) {
    const { w, h, type } = variant;
    const size =
      variant._ === 'PhotoSize'
        ? variant.size
        : variant._ === 'PhotoSizeProgressive'
          ? variant.sizes?.at(-1)
          : undefined;
    if (
      size === undefined ||
      !Number.isSafeInteger(size) ||
      size <= 0 ||
      !w ||
      !h ||
      w <= 0 ||
      h <= 0 ||
      !/^[a-z]$/.test(type)
    )
      continue;
    const area = w * h;
    if (!best || area > best.area || (area === best.area && size > best.size))
      best = { thumbSize: type, size, area };
  }
  if (!best) throw securityError('Photo has no downloadable size');
  return best;
}

function messageFile(media?: Media) {
  const photo = media?._ === 'MessageMediaPhoto' ? media.photo : undefined;
  const document =
    media?._ === 'MessageMediaDocument' ? media.document : undefined;
  let file: Partial<FileReference> | undefined;
  let size: number, thumbSize: string, extension: string | undefined;
  let constructor: string;
  let check: 'image' | 'audio' | undefined;
  if (photo?._ === 'Photo') {
    ({ size, thumbSize } = largestPhoto(photo));
    file = photo;
    constructor = 'InputPhotoFileLocation';
    check = 'image';
  } else if (document?._ === 'Document') {
    const attributes = document.attributes ?? [];
    const filename = attributes.find(
      (attribute) => attribute._ === 'DocumentAttributeFilename',
    )?.fileName;
    // Use a bounded ASCII suffix, never the sender's path or basename.
    const suffix = /\.([a-z0-9]{1,16})$/i
      .exec(filename ?? '')?.[1]
      .toLowerCase();
    const mime = document.mimeType.toLowerCase();
    const generic = mime === 'application/octet-stream' || !mime;
    const audioHint =
      generic &&
      (media?.voice ||
        attributes.some((attr) => attr._ === 'DocumentAttributeAudio'));
    const image =
      imageTypes.get(mime) ??
      (generic && suffix ? imageSuffixes.get(suffix) : undefined);
    const audio =
      audioTypes.get(mime) ??
      (generic && suffix ? audioSuffixes.get(suffix) : undefined);
    if (audioHint && (!suffix || audio)) {
      check = 'audio';
    } else {
      extension = image ?? audio ?? suffix ?? attachmentTypes.get(mime);
      check = image ? 'image' : audio ? 'audio' : undefined;
    }
    size = Number(document.size);
    thumbSize = '';
    file = document;
    constructor = 'InputDocumentFileLocation';
  } else {
    throw securityError('Message does not contain a downloadable attachment');
  }
  if (
    !Number.isSafeInteger(size) ||
    size <= 0 ||
    size > MAX_DOWNLOAD_MIB * 1024 * 1024
  )
    throw securityError(
      `File size must be between 1 byte and ${MAX_DOWNLOAD_MIB} MiB`,
    );
  const { id, accessHash, fileReference, dcId } = file;
  if (
    typeof id !== 'bigint' ||
    !id ||
    typeof accessHash !== 'bigint' ||
    !Buffer.isBuffer(fileReference) ||
    !fileReference.length ||
    fileReference.length > 4096 ||
    typeof dcId !== 'number'
  )
    throw protocolError('Invalid media file reference');
  return {
    size,
    dcId,
    check,
    extension,
    location: { _: constructor, id, accessHash, fileReference, thumbSize },
  };
}

function preview(text: string) {
  let count = 0,
    end = 0;
  for (const character of text) {
    if (count++ === 160)
      return { lastMessage: text.slice(0, end), previewTruncated: true };
    end += character.length;
  }
  return { lastMessage: text, previewTruncated: false };
}

function indexMessagesById(messages: WireMessage[]) {
  const index = new Map<number, WireMessage[]>();
  for (const message of messages) {
    const matches = index.get(message.id);
    if (matches) matches.push(message);
    else index.set(message.id, [message]);
  }
  return index;
}

type ClientHooks = {
  secret?: (question: string) => Promise<Buffer>;
  audit?: (entry: AuditRecord) => Promise<unknown>;
  warning?: (message: string) => void;
  mediaRpc?: ReturnType<typeof createMediaRpc>;
};
type Attachment = Awaited<ReturnType<typeof openAttachment>>;

export function createTelegram(
  rpc: RpcClient,
  {
    secret = async () => {
      throw approvalError('Interactive 2FA is required');
    },
    audit = async () => {},
    warning = () => {},
    mediaRpc,
  }: ClientHooks = {},
) {
  const entities: EntityCache = new Map();
  let cachedDialogs: DialogSummary[] | undefined;
  let accountUser: Entity | undefined;

  async function call<T = unknown>(
    name: string,
    args: object = {},
    options?: RpcOptions,
  ): Promise<T> {
    const result = await rpc.invoke(name, args, options);
    return ingestEntities(entities, result) as T;
  }
  async function getMe() {
    if (!accountUser) {
      const users = (await rpc.invoke('users.GetUsers', {
        id: [{ _: 'InputUserSelf' }],
      })) as Entity[];
      const me = users.find((item) => item._ === 'User' && item.self);
      if (!me || me.bot)
        throw securityError('An authorized human Telegram account is required');
      rememberEntity(entities, me);
      accountUser = me;
    }
    return accountUser;
  }

  async function whoami() {
    const me = await getMe();
    return {
      id: peerKey(me),
      firstName: me.firstName,
      lastName: me.lastName,
      username: me.username,
      phone: me.phone,
      isBot: Boolean(me.bot),
    };
  }

  async function fetchDialogs(maximum: number, complete: boolean) {
    const chats = new Map<string, DialogSummary>();
    let offsetDate = 0,
      offsetId = 0,
      offsetPeer: TLObject = { _: 'InputPeerEmpty' },
      cursor: string | undefined;
    for (let page = 0; page < 200; page++) {
      const result = await call<{
        _: string;
        dialogs: Dialog[];
        messages?: WireMessage[];
      }>('messages.GetDialogs', {
        excludePinned: page > 0,
        offsetDate,
        offsetId,
        offsetPeer,
        limit: 100,
        hash: 0n,
      });
      if (!Array.isArray(result.dialogs))
        throw protocolError('Unexpected dialogs result');
      const raw = result.dialogs.filter((dialog) => dialog._ === 'Dialog');
      const messages = indexMessagesById(result.messages ?? []);
      let lastMessage: WireMessage | undefined, lastKey: string | undefined;
      for (const dialog of raw) {
        const key = peerKey(dialog.peer),
          entity = entities.get(key);
        if (!entity) throw protocolError('Dialog omitted its entity');
        const info = summarizePeer(entity, dialog);
        // Message IDs can collide across chats; both ID and peer must match.
        const message = messages
          .get(dialog.topMessage)
          ?.find((item) => item.peerId && peerKey(item.peerId) === key);
        if (message) {
          Object.assign(
            info,
            preview(message.message ?? ''),
            message.date ? { lastMessageDate: isoSeconds(message.date) } : {},
          );
        }
        lastMessage = message;
        lastKey = key;
        chats.set(key, info);
      }
      if (complete && chats.size > maximum)
        throw securityError(
          'Dialog discovery limit exceeded; refusing incomplete name' +
            ' resolution',
        );
      if (!complete && chats.size >= maximum)
        return [...chats.values()].slice(0, maximum);
      if (
        result._ === 'messages.Dialogs' ||
        result.dialogs.length < 100 ||
        !raw.length
      )
        return [...chats.values()];
      const last = raw.at(-1)!;
      if (!lastMessage?.date)
        throw protocolError('Cannot safely advance the dialog cursor');
      const next = `${lastKey}:${last.topMessage}:${lastMessage.date}`;
      if (next === cursor)
        throw protocolError('Dialog pagination made no progress');
      cursor = next;
      offsetId = last.topMessage;
      offsetDate = lastMessage.date;
      offsetPeer = inputPeer(entities.get(lastKey!));
    }
    throw securityError('Dialog pagination budget exceeded');
  }

  async function listDialogs({
    limit = 100,
    type,
    unread = false,
    admin = false,
  }: {
    limit?: number;
    type?: string;
    unread?: boolean;
    admin?: boolean;
  } = {}) {
    positiveLimit(limit);
    const needFilter = Boolean(type || unread || admin);
    const chats = await fetchDialogs(needFilter ? 10_000 : limit, needFilter);
    return chats
      .filter(
        (chat) =>
          (!type ||
            chat.type === type ||
            (type === 'groups' &&
              ['group', 'supergroup'].includes(chat.type))) &&
          (!unread || (chat.unreadCount ?? 0) > 0 || chat.unreadMark) &&
          (!admin || chat.isAdmin),
      )
      .slice(0, limit);
  }

  async function getAllDialogs() {
    return (cachedDialogs ??= await fetchDialogs(10_000, true));
  }
  async function resolvePeer(identifier: string) {
    if (
      typeof identifier !== 'string' ||
      !identifier.length ||
      identifier.length > 256 ||
      !identifier.isWellFormed() ||
      identifier.includes('\0')
    )
      throw securityError('Invalid or excessively long peer identifier');
    if (identifier === 'self') return getMe();
    const numeric = parsePeerId(identifier);
    if (identifier.startsWith('@')) {
      if (!/^@[A-Za-z0-9_]{1,32}$/.test(identifier))
        throw securityError('Invalid Telegram username');
      const result = await call<{ peer: Peer }>('contacts.ResolveUsername', {
        username: identifier.slice(1),
      });
      const entity = entities.get(peerKey(result.peer));
      if (!entity)
        throw protocolError('Username resolution omitted its entity');
      inputPeer(entity);
      return entity;
    }
    if (numeric) {
      const known = entities.get(numeric.key);
      if (!known || known.min || known._ === 'UserEmpty') await getAllDialogs();
      const entity = entities.get(numeric.key);
      if (!entity)
        throw securityError(
          'Peer ID is not in known dialogs. Resolve its explicit' +
            ' @username first; IDs are never treated as titles.',
        );
      inputPeer(entity);
      return entity;
    }
    const key = exactNameMatch(await getAllDialogs(), identifier);
    const entity = entities.get(key);
    inputPeer(entity);
    return entity!;
  }

  function projectMessage(
    message: WireMessage,
    chatId = message.peerId ? peerKey(message.peerId) : undefined,
  ) {
    let senderId = message.fromId ? peerKey(message.fromId) : undefined;
    if (!senderId && message.peerId?._ === 'PeerUser')
      senderId = message.out
        ? accountUser
          ? peerKey(accountUser)
          : undefined
        : chatId;
    else if (!senderId && message.peerId?._ === 'PeerChannel' && message.post)
      senderId = chatId;
    const sender = senderId && entities.get(senderId);
    return {
      id: message.id,
      chatId,
      date: message.date !== undefined ? isoSeconds(message.date) : undefined,
      senderId,
      sender: sender ? entityTitle(sender) : undefined,
      text: message.message ?? '',
      outgoing: Boolean(message.out),
      replyToMsgId: message.replyTo?.replyToMsgId,
      ...(message._ === 'MessageService'
        ? { service: message.action?._ ?? 'Unknown' }
        : {}),
      ...(message.media ? { media: mediaInfo(message.media) } : {}),
    };
  }

  async function* getHistory(
    entity: Entity,
    {
      limit = 50,
      since,
      until,
      minId = 0,
      includeService = false,
    }: HistoryOptions = {},
  ) {
    positiveLimit(limit, 1_000_001);
    if (
      (since !== undefined &&
        (!Number.isInteger(since) || since < 0 || since > 2_147_483_647)) ||
      (until !== undefined &&
        (!Number.isInteger(until) || until < 0 || until > 2_147_483_647)) ||
      (since !== undefined && until !== undefined && since > until)
    )
      throw securityError('Invalid history date range');
    const input = inputPeer(entity),
      chatId = peerKey(entity);
    // Telegram offsetDate is exclusive, while our until is inclusive. At the
    // signed-int ceiling, omit the server offset and filter locally instead.
    const initialDate =
      until !== undefined && until < 2_147_483_647 ? until + 1 : 0;
    let offsetId = 0,
      yielded = 0;
    for (let pages = 0; pages < 20_000 && yielded < limit; pages++) {
      const result = await call<{ messages: WireMessage[] }>(
        'messages.GetHistory',
        {
          peer: input,
          offsetId,
          offsetDate: offsetId ? 0 : initialDate,
          addOffset: 0,
          limit: 100,
          maxId: 0,
          minId,
          hash: 0n,
        },
      );
      if (!Array.isArray(result.messages))
        throw protocolError('Unexpected history result');
      if (!result.messages.length) return;
      let oldest = offsetId || 2_147_483_647,
        reached = false;
      for (const message of result.messages) {
        if (!Number.isInteger(message.id) || message.id <= 0)
          throw protocolError('Invalid message ID in history');
        oldest = Math.min(oldest, message.id);
        if (message.id <= minId) {
          reached = true;
          continue;
        }
        if (since !== undefined && message.date! < since) {
          reached = true;
          continue;
        }
        if (until !== undefined && message.date! > until) continue;
        if (
          message._ !== 'Message' &&
          !(includeService && message._ === 'MessageService')
        )
          continue;
        if (!message.peerId || peerKey(message.peerId) !== chatId)
          throw securityError('History response contains a different chat');
        yield projectMessage(message, chatId);
        yielded++;
        if (yielded >= limit) return;
      }
      if (reached || result.messages.length < 100) return;
      if (oldest <= 0 || (offsetId && oldest >= offsetId))
        throw protocolError('History pagination made no progress');
      offsetId = oldest;
    }
    if (yielded < limit) throw securityError('History page budget exceeded');
  }

  async function read(identifier: string, options: HistoryOptions = {}) {
    const entity = await resolvePeer(identifier),
      messages = [];
    for await (const message of getHistory(entity, options))
      messages.push(message);
    return { chat: summarizePeer(entity), messages };
  }

  async function lookupMessage(entity: Entity, messageId: number) {
    const id = [{ _: 'InputMessageID', id: messageId }];
    const page =
      peerKind(entity) === 'channel'
        ? await call<{ messages: WireMessage[] }>('channels.GetMessages', {
            channel: inputChannel(entity),
            id,
          })
        : await call<{ messages: WireMessage[] }>('messages.GetMessages', {
            id,
          });
    if (!Array.isArray(page?.messages) || page.messages.length > 1)
      throw protocolError('Unexpected single-message result');
    const [message] = page.messages;
    if (
      !message ||
      message._ !== 'Message' ||
      message.id !== messageId ||
      !message.peerId ||
      peerKey(message.peerId) !== peerKey(entity)
    )
      throw securityError('Message not found in the specified chat');
    return message;
  }

  async function downloadMedia(
    identifier: string,
    messageId: number,
    directory: string,
  ) {
    positiveLimit(messageId, 2_147_483_647);
    if (!mediaRpc) throw protocolError('Media connection is not configured');
    const entity = await resolvePeer(identifier);
    const chatId = peerKey(entity);
    const lookup = async () => {
      const message = await lookupMessage(entity, messageId);
      if (
        entity.noforwards ||
        entities.get(chatId)?.noforwards ||
        message.noforwards ||
        message.ttlPeriod !== undefined ||
        message.media?.ttlSeconds !== undefined
      )
        throw securityError('Protected or disappearing media cannot be saved');
      return { message, file: messageFile(message.media) };
    };
    const { message, file } = await lookup();
    const accountId = peerId(await getMe());
    let { location } = file;
    const output = await downloadTemporary(directory);
    try {
      const extension = await mediaRpc(file.dcId, accountId, async (conn) => {
        let extension: string | undefined;
        let refreshed = false;
        for (let offset = 0; offset < file.size;) {
          let part;
          try {
            part = (await conn.invoke('upload.GetFile', {
              location,
              offset: BigInt(offset),
              limit: FILE_CHUNK,
            })) as { _: string; bytes?: Buffer };
          } catch (error) {
            if (
              refreshed ||
              !isRpcError(error) ||
              !/^FILE_REFERENCE_(EXPIRED|INVALID)$/.test(error.errorMessage)
            )
              throw error;
            const fresh = (await lookup()).file;
            if (
              fresh.dcId !== file.dcId ||
              fresh.size !== file.size ||
              fresh.check !== file.check ||
              fresh.extension !== file.extension ||
              fresh.location._ !== location._ ||
              fresh.location.id !== location.id ||
              fresh.location.accessHash !== location.accessHash ||
              fresh.location.thumbSize !== location.thumbSize
            )
              throw securityError('Media changed while downloading');
            location = fresh.location;
            refreshed = true;
            continue;
          }
          if (part?._ === 'upload.FileCdnRedirect')
            throw protocolError('Telegram CDN downloads are not supported');
          const expected = Math.min(FILE_CHUNK, file.size - offset);
          if (
            part?._ !== 'upload.File' ||
            !Buffer.isBuffer(part.bytes) ||
            part.bytes.length !== expected
          )
            throw protocolError('Invalid media chunk length');
          if (!extension) {
            const detected =
              file.check === 'image'
                ? imageExtension(part.bytes)
                : file.check === 'audio'
                  ? audioExtension(part.bytes)
                  : file.extension;
            // Preserve the bytes of mislabeled files without the claimed type.
            extension =
              detected && (!file.extension || file.extension === detected)
                ? detected
                : 'bin';
          }
          await output.handle.writeFile(part.bytes);
          offset += part.bytes.length;
        }
        return extension!;
      });
      const filename = `${chatId.replace(':', '-')}-${messageId}.${extension}`;
      await output.commit(filename);
      return {
        message: projectMessage(message, chatId),
        path: join(output.directory, filename),
        bytes: file.size,
      };
    } finally {
      await output.dispose();
    }
  }

  async function search(
    query: string,
    { chat, limit = 50 }: { chat?: string; limit?: number } = {},
  ) {
    positiveLimit(limit);
    if (
      typeof query !== 'string' ||
      !query.length ||
      Buffer.byteLength(query) > 1024
    )
      throw securityError(
        'Search text must be nonempty and at most 1024 bytes',
      );
    const entity = chat ? await resolvePeer(chat) : undefined;
    const peer = entity && inputPeer(entity),
      chatId = entity && peerKey(entity);
    let offsetId = 0,
      offsetPeer: TLObject = { _: 'InputPeerEmpty' },
      offsetRate = 0,
      previous: string | undefined;
    const messages = [],
      seen = new Set();
    let pages = 0;
    while (messages.length < limit) {
      if (++pages > 1000) throw securityError('Search page budget exceeded');
      const common: {
        q: string;
        filter: TLObject;
        minDate: number;
        maxDate: number;
        offsetId: number;
        limit: number;
      } = {
        q: query,
        filter: { _: 'InputMessagesFilterEmpty' },
        minDate: 0,
        maxDate: 0,
        offsetId,
        limit: Math.min(100, limit - messages.length),
      };
      const result: SearchPage = peer
        ? await call<SearchPage>('messages.Search', {
            ...common,
            peer,
            addOffset: 0,
            maxId: 0,
            minId: 0,
            hash: 0n,
          })
        : await call<SearchPage>('messages.SearchGlobal', {
            ...common,
            offsetRate,
            offsetPeer,
          });
      if (!Array.isArray(result.messages))
        throw protocolError('Unexpected search result');
      for (const message of result.messages) {
        if (message._ !== 'Message') continue;
        const id = peerKey(message.peerId);
        if (chatId && id !== chatId)
          throw securityError('Scoped search returned a different chat');
        const key = `${id}:${message.id}`;
        if (!seen.has(key)) {
          seen.add(key);
          messages.push(projectMessage(message, id));
        }
        if (messages.length >= limit) break;
      }
      if (messages.length >= limit) break;
      if (!result.messages.length || result.messages.length < common.limit)
        break;
      const last = result.messages.at(-1)!;
      if (!last.peerId) throw protocolError('Cannot advance search cursor');
      offsetId = last.id;
      offsetRate = result.nextRate ?? 0;
      const id = peerKey(last.peerId);
      if (!peer) offsetPeer = inputPeer(entities.get(id));
      const cursor = `${id}:${offsetId}:${offsetRate}`;
      if (cursor === previous)
        throw protocolError('Search pagination made no progress');
      previous = cursor;
      if (seen.size > 10_000)
        throw securityError('Search result budget exceeded');
    }
    return { ...(entity ? { chat: summarizePeer(entity) } : {}), messages };
  }

  async function contact(identifier: string) {
    const entity = await resolvePeer(identifier);
    const result = await call<{ fullUser?: { about?: string } }>(
      'users.GetFullUser',
      { id: inputUser(entity) },
    );
    return {
      ...summarizePeer(entity),
      firstName: entity.firstName,
      lastName: entity.lastName,
      phone: entity.phone,
      bio: result.fullUser?.about,
      isBot: Boolean(entity.bot),
      isMutualContact: Boolean(entity.mutualContact),
    };
  }

  async function getChat(identifier: string) {
    const entity = await resolvePeer(identifier);
    if (peerKind(entity) === 'user') return contact(peerKey(entity));
    const result = await call<FullChat>(
      entity._ === 'Chat' ? 'messages.GetFullChat' : 'channels.GetFullChannel',
      entity._ === 'Chat'
        ? { chatId: entity.id }
        : { channel: inputChannel(entity) },
    );
    const full = result.fullChat;
    return {
      ...summarizePeer(entities.get(peerKey(entity)) ?? entity),
      about: full?.about,
      participantsCount: full?.participantsCount ?? entity.participantsCount,
      adminsCount: full?.adminsCount,
      linkedChatId: full?.linkedChatId?.toString(),
    };
  }

  async function members(
    identifier: string,
    { admins = false, limit = 200 } = {},
  ) {
    positiveLimit(limit);
    const entity = await resolvePeer(identifier);
    if (entity._ === 'User')
      throw securityError('Members require a group/channel');
    const participants: Participant[] = [];
    if (entity._ === 'Chat') {
      const result = await call<FullChat>('messages.GetFullChat', {
        chatId: entity.id,
      });
      if (result.fullChat?.participants?._ !== 'ChatParticipants')
        throw securityError('Group participant list is not available');
      participants.push(...result.fullChat.participants.participants);
    } else {
      for (let offset = 0; participants.length < limit;) {
        const pageLimit = Math.min(200, limit - participants.length);
        const result = await call<Participants>('channels.GetParticipants', {
          channel: inputChannel(entity),
          filter: {
            _: admins
              ? 'ChannelParticipantsAdmins'
              : 'ChannelParticipantsRecent',
          },
          offset,
          limit: pageLimit,
          hash: 0n,
        });
        if (!Array.isArray(result.participants))
          throw protocolError('Unexpected participant list');
        participants.push(...result.participants);
        offset += result.participants.length;
        if (result.participants.length < pageLimit) break;
      }
    }
    const members = participants
      .map((participant) => {
        const id =
          participant.userId ??
          (participant.peer?._ === 'PeerUser'
            ? participant.peer.userId
            : undefined);
        if (id === undefined) return undefined;
        const user = entities.get(`user:${id}`);
        const creator = participant._.endsWith('Creator'),
          admin = creator || participant._.endsWith('Admin');
        return {
          id: `user:${id}`,
          name: user ? entityTitle(user) : 'Unknown',
          username: user?.username,
          role: creator ? 'owner' : admin ? 'admin' : 'member',
          isAdmin: admin,
        };
      })
      .filter((member) => member && (!admins || member.isAdmin))
      .slice(0, limit);
    return { chat: summarizePeer(entity), members };
  }

  async function mutation<T>(
    command: string,
    targets: Entity[],
    details: object,
    perform: () => Promise<T>,
  ) {
    const me = await getMe();
    const account = peerKey(me);
    if (
      ['kick', 'promote', 'transfer-owner'].includes(command) &&
      peerKey(targets.at(-1)) === account
    )
      throw securityError(
        'Administrative target must be a different user; account IDs,' +
          ' not profile flags, determine this',
      );
    const plan = {
      command,
      account: { id: account, title: entityTitle(me), username: me.username },
      peers: targets.map((entity) => ({
        id: peerKey(entity),
        title: entityTitle(entity),
        username: entity.username,
      })),
      ...details,
    };
    const digest = sha256(Buffer.from(safeJson(plan, 0))).toString('hex');
    const logOutcome = (status: AuditStatus, error?: string) =>
      audit({
        command,
        account,
        peers: plan.peers.map((peer) => peer.id),
        digest,
        status,
        ...(error && { error }),
      });
    await logOutcome('requested');
    let result;
    try {
      result = await perform();
    } catch (error) {
      await logOutcome(
        isAmbiguousMutationError(error) ? 'unknown' : 'failed',
        (error as Error).name,
      ).catch(() =>
        warning(
          'Could not record mutation failure; inspect Telegram before' +
            ' retrying.',
        ),
      );
      throw error;
    }
    await logOutcome('succeeded').catch(() =>
      warning(
        'The Telegram operation succeeded, but its audit outcome' +
          ' could not be saved. Do not repeat it.',
      ),
    );
    return result;
  }

  async function deleteMessage(
    identifier: string,
    messageId: number,
    scope: 'me' | 'everyone',
  ) {
    positiveLimit(messageId, 2_147_483_647);
    if (scope !== 'me' && scope !== 'everyone')
      throw securityError('Choose a deletion scope: me or everyone');
    const entity = await resolvePeer(identifier);
    const channel =
      peerKind(entity) === 'channel' ? inputChannel(entity) : null;
    if (channel && scope === 'me')
      throw securityError('Channels and supergroups require --for-everyone');
    // The non-channel delete RPC takes IDs without a peer. Verify the chat
    // on the exact message first, also for channel-scoped deletions.
    await lookupMessage(entity, messageId);
    const id = [messageId];
    const [name, args]: RpcRequest = channel
      ? ['channels.DeleteMessages', { channel, id }]
      : ['messages.DeleteMessages', { id, revoke: scope === 'everyone' }];
    return mutation('delete', [entity], { messageId, scope }, async () => {
      const result = await call<{ _: string }>(name, args, { mutation: true });
      if (result?._ !== 'messages.AffectedMessages')
        throw ambiguousMutationError();
      return { success: true, chatId: peerKey(entity), messageId, scope };
    });
  }

  async function send(
    identifier: string,
    text: string,
    { replyTo, attachment }: { replyTo?: number; attachment?: Attachment } = {},
  ) {
    if (!attachment || text !== '') validateMessageText(text);
    if (
      replyTo !== undefined &&
      (!Number.isInteger(replyTo) || replyTo < 1 || replyTo > 2_147_483_647)
    )
      throw securityError('Invalid reply message ID');
    const entity = await resolvePeer(identifier),
      input = inputPeer(entity);
    const randomId = randomLong() || 1n;
    const args = {
      peer: input,
      message: text,
      randomId,
      ...(replyTo
        ? { replyTo: { _: 'InputReplyToMessage', replyToMsgId: replyTo } }
        : {}),
    };
    const file = attachment && {
      fileName: attachment.name,
      size: attachment.size,
    };
    return mutation(
      replyTo ? 'reply' : 'send',
      [entity],
      {
        message: text,
        ...(file ? { file } : {}),
        ...(replyTo ? { replyToMsgId: replyTo } : {}),
      },
      async () => {
        let result: SendResult;
        if (attachment) {
          const uploaded = await attachment.upload(rpc);
          const media = {
            _: 'InputMediaUploadedDocument',
            file: uploaded,
            forceFile: true,
            mimeType: 'application/octet-stream',
            attributes: [
              { _: 'DocumentAttributeFilename', fileName: file!.fileName },
            ],
          };
          result = await call<SendResult>(
            'messages.SendMedia',
            { ...args, media },
            { mutation: true },
          );
        } else
          result = await call<SendResult>(
            'messages.SendMessage',
            { ...args, noWebpage: true },
            { mutation: true },
          );
        const updates =
          result._ === 'UpdateShort' ? [result.update] : result.updates;
        const sent =
          result._ === 'UpdateShortSentMessage'
            ? result
            : (updates?.find(
                (update) =>
                  update._ === 'UpdateMessageID' &&
                  update.randomId === randomId,
              ) ??
              (!attachment
                ? updates?.find((update) => update.message?.out)
                : undefined));
        return {
          success: true,
          chatId: peerKey(entity),
          messageId: sent?.id ?? sent?.message?.id,
          randomId: randomId.toString(),
          ...(file ? { file } : {}),
        };
      },
    );
  }

  async function mute(identifier: string, until = 2_147_483_647) {
    if (
      !Number.isInteger(until) ||
      until < 0 ||
      until > 2_147_483_647 ||
      (until > 0 && until <= epochSeconds())
    )
      throw securityError('Invalid mute expiry');
    const entity = await resolvePeer(identifier),
      peer = inputPeer(entity);
    return mutation(
      until === 0 ? 'unmute' : 'mute',
      [entity],
      { muteUntil: until === 0 ? null : isoSeconds(until) },
      async () => {
        const result = await call(
          'account.UpdateNotifySettings',
          {
            peer: { _: 'InputNotifyPeer', peer },
            settings: { _: 'InputPeerNotifySettings', muteUntil: until },
          },
          { mutation: true },
        );
        if (result !== true)
          throw protocolError(
            'Telegram did not confirm the notification change',
          );
        return { success: true, chatId: peerKey(entity), muteUntil: until };
      },
    );
  }

  async function kick(group: string, userIdentifier: string) {
    const entity = await resolvePeer(group);
    if (entity._ === 'User') throw securityError('Kick requires a group');
    const user = await groupUser(entity, userIdentifier);
    if (user._ !== 'User' || user.self)
      throw securityError('Kick requires a different user');
    const request: RpcRequest =
      entity._ === 'Chat'
        ? [
            'messages.DeleteChatUser',
            {
              chatId: entity.id,
              userId: inputUser(user),
              revokeHistory: false,
            },
          ]
        : [
            'channels.EditBanned',
            {
              channel: inputChannel(entity),
              participant: inputPeer(user),
              bannedRights: {
                _: 'ChatBannedRights',
                untilDate: 0,
                viewMessages: true,
              },
            },
          ];
    return mutation(
      'kick',
      [entity, user],
      {
        effect:
          entity._ === 'Chat'
            ? 'Remove member without revoking history'
            : 'Permanently ban member from viewing this channel/supergroup',
      },
      async () => {
        await call(...request, { mutation: true });
        return {
          success: true,
          chatId: peerKey(entity),
          userId: peerKey(user),
        };
      },
    );
  }

  async function promote(
    group: string,
    userIdentifier: string,
    { rights, rank = '' }: { rights?: string[] | 'full'; rank?: string } = {},
  ) {
    const entity = await resolvePeer(group);
    if (entity._ === 'User')
      throw securityError('Promotion requires a group/channel');
    const user = await groupUser(entity, userIdentifier);
    if (
      user._ !== 'User' ||
      user.self ||
      typeof rank !== 'string' ||
      rank.length > 16
    )
      throw securityError(
        'Invalid promotion target or rank (maximum 16 characters)',
      );
    let request: RpcRequest;
    if (entity._ === 'Chat') {
      if (rights !== 'full')
        throw securityError(
          'Basic groups only support all-or-nothing admin status;' +
            ' explicitly use --rights full',
        );
      if (rank)
        throw securityError('Basic groups do not support custom admin ranks');
      request = [
        'messages.EditChatAdmin',
        { chatId: entity.id, userId: inputUser(user), isAdmin: true },
      ];
    } else {
      if (
        !Array.isArray(rights) ||
        !rights.length ||
        rights.some((right) => !ADMIN_RIGHTS.includes(right))
      )
        throw securityError(
          'Supply an explicit nonempty list of supported admin rights;' +
            ' no broad default is granted',
        );
      request = [
        'channels.EditAdmin',
        {
          channel: inputChannel(entity),
          userId: inputUser(user),
          adminRights: {
            _: 'ChatAdminRights',
            ...Object.fromEntries(rights.map((right) => [right, true])),
          },
          rank,
        },
      ];
    }
    return mutation('promote', [entity, user], { rights, rank }, async () => {
      const result = await call(...request, { mutation: true });
      if (entity._ === 'Chat' && result !== true)
        throw protocolError('Telegram did not confirm promotion');
      return {
        success: true,
        chatId: peerKey(entity),
        userId: peerKey(user),
        rights,
      };
    });
  }

  async function transferOwner(group: string, userIdentifier: string) {
    const entity = await resolvePeer(group);
    if (entity._ === 'User' || !entity.creator)
      throw securityError('Ownership transfer requires an owned group/channel');
    const user = await groupUser(entity, userIdentifier);
    if (user._ !== 'User' || user.self || user.bot)
      throw securityError(
        'Ownership transfer requires a different non-bot user',
      );
    if (entity._ === 'Chat') {
      const result = await call<FullChat>('messages.GetFullChat', {
        chatId: entity.id,
      });
      if (
        !result.fullChat?.participants?.participants?.some(
          (participant) => participant.userId === user.id,
        )
      )
        throw securityError('New owner must already be a member');
    } else {
      const result = await call<{ participant?: Participant }>(
        'channels.GetParticipant',
        {
          channel: inputChannel(entity),
          participant: inputPeer(user),
        },
      );
      if (
        !result.participant ||
        result.participant.userId !== user.id ||
        result.participant._ === 'ChannelParticipantLeft' ||
        result.participant._ === 'ChannelParticipantBanned'
      )
        throw securityError('New owner must already be a member');
    }
    const peer = inputPeer(entity),
      userId = inputUser(user);
    return mutation(
      'transfer-owner',
      [entity, user],
      {
        irreversible: true,
        effect: 'You lose ownership. Only the new owner can transfer it back.',
      },
      async () => {
        const info = await call<PasswordParameters>('account.GetPassword');
        const password = await secret('Telegram 2FA password: ');
        try {
          const check = await passwordCheck(info, password);
          await call(
            'messages.EditChatCreator',
            { peer, userId, password: check },
            { mutation: true },
          );
          return {
            success: true,
            chatId: peerKey(entity),
            newOwner: peerKey(user),
          };
        } finally {
          password.fill(0);
        }
      },
    );
  }

  async function rawFolders() {
    await getMe();
    const result = await call<{ filters: FolderFilter[] }>(
      'messages.GetDialogFilters',
    );
    if (!Array.isArray(result.filters))
      throw protocolError('Unexpected folder response');
    return result.filters;
  }

  function folderSummary(filter: FolderFilter) {
    return {
      id: `folder:${filter.id ?? 0}`,
      title:
        typeof filter.title === 'string'
          ? filter.title
          : (filter.title?.text ?? 'All chats'),
      type: filter._,
      included: (filter.includePeers ?? []).map((peer) => folderPeerKey(peer)),
      pinned: (filter.pinnedPeers ?? []).map((peer) => folderPeerKey(peer)),
      excluded: (filter.excludePeers ?? []).map((peer) => folderPeerKey(peer)),
      automatic: Object.fromEntries(
        [
          'contacts',
          'nonContacts',
          'groups',
          'broadcasts',
          'bots',
          'excludeMuted',
          'excludeRead',
          'excludeArchived',
        ]
          .filter((name) => filter[name])
          .map((name) => [name, true]),
      ),
    };
  }

  async function listFolders() {
    return (await rawFolders()).map((filter) => folderSummary(filter));
  }
  function findFolder(filters: FolderFilter[], identifier: string) {
    const numeric = /^(?:folder:)?([1-9][0-9]*)$/.exec(identifier);
    const matches = filters.filter((filter) =>
      numeric
        ? filter.id === Number(numeric[1])
        : (typeof filter.title === 'string'
            ? filter.title
            : filter.title?.text
          )?.toLowerCase() === identifier.toLowerCase(),
    );
    if (
      matches.length !== 1 ||
      !['DialogFilter', 'DialogFilterChatlist'].includes(matches[0]._)
    )
      throw securityError(
        'Folder not found, ambiguous, or not editable; use a stable' +
          ' folder:<id>',
      );
    return matches[0];
  }

  async function getFolder(identifier: string) {
    return folderSummary(findFolder(await rawFolders(), identifier));
  }
  async function changeFolder(identifier: string, chat: string, add: boolean) {
    const entity = await resolvePeer(chat),
      key = peerKey(entity),
      input = inputPeer(entity);
    const filter = findFolder(await rawFolders(), identifier);
    const fingerprint = sha256(Buffer.from(safeJson(filter, 0))).toString(
      'hex',
    );
    const updated = {
      ...filter,
      pinnedPeers: add
        ? [...filter.pinnedPeers!]
        : filter.pinnedPeers!.filter((peer) => folderPeerKey(peer) !== key),
      includePeers: filter.includePeers!.filter(
        (peer) => folderPeerKey(peer) !== key,
      ),
    };
    if (filter._ === 'DialogFilter')
      updated.excludePeers = filter.excludePeers!.filter(
        (peer) => folderPeerKey(peer) !== key,
      );
    if (add) updated.includePeers.push(input);
    else if (filter._ === 'DialogFilter') updated.excludePeers!.push(input);
    const command = add ? 'folder-add' : 'folder-remove';
    return mutation(
      command,
      [entity],
      {
        folder: folderSummary(filter),
        effect: add
          ? 'Explicitly include chat and remove any exclusion'
          : 'Remove explicit/pinned membership; standard folders also' +
            ' explicitly exclude the chat',
      },
      async () => {
        const fresh = findFolder(await rawFolders(), `folder:${filter.id}`);
        if (
          sha256(Buffer.from(safeJson(fresh, 0))).toString('hex') !==
          fingerprint
        )
          throw securityError(
            'Folder changed before update; retry with fresh state',
          );
        if (
          (await call(
            'messages.UpdateDialogFilter',
            { id: filter.id, filter: updated },
            { mutation: true },
          )) !== true
        )
          throw protocolError('Telegram did not confirm folder update');
        return { success: true, folderId: `folder:${filter.id}`, chatId: key };
      },
    );
  }

  async function createFolder(
    title: string,
    {
      peers = [],
      categories = [],
    }: { peers?: string[]; categories?: string[] } = {},
  ) {
    if (
      typeof title !== 'string' ||
      !title.length ||
      title.length > 12 ||
      !title.isWellFormed()
    )
      throw securityError('Folder title must be 1–12 well-formed characters');
    if (
      !Array.isArray(peers) ||
      peers.length > 100 ||
      peers.some((peer) => typeof peer !== 'string' || !peer.length) ||
      !Array.isArray(categories) ||
      categories.some((category) => !FOLDER_CATEGORIES.includes(category)) ||
      (!peers.length && !categories.length)
    )
      throw securityError(
        'Folder creation requires explicit initial peers or inclusion' +
          ' categories',
      );
    const initial = new Map<string, Entity>();
    for (const identifier of peers) {
      const entity = await resolvePeer(identifier);
      initial.set(peerKey(entity), entity);
    }
    const included = [...initial.values()],
      automatic = Object.fromEntries(
        categories.map((category) => [category, true]),
      );
    const filters = await rawFolders();
    if (
      filters.some(
        (filter) =>
          folderSummary(filter).title.toLowerCase() === title.toLowerCase(),
      )
    )
      throw securityError('A folder with that exact name already exists');
    let id = 2;
    while (filters.some((filter) => filter.id === id)) id++;
    const me = await getMe();
    const filter = {
      _: 'DialogFilter',
      id,
      title: { _: 'TextWithEntities', text: title, entities: [] },
      ...automatic,
      pinnedPeers: [],
      includePeers: included.map((entity) => inputPeer(entity)),
      excludePeers: [],
    };
    return mutation(
      'folder-create',
      included.length ? included : [me],
      {
        folderId: `folder:${id}`,
        title,
        included: [...initial.keys()],
        categories: Object.keys(automatic),
      },
      async () => {
        const current = await rawFolders();
        if (
          current.some(
            (filter) =>
              filter.id === id ||
              folderSummary(filter).title.toLowerCase() === title.toLowerCase(),
          )
        )
          throw securityError('Folder list changed before creation');
        if (
          (await call(
            'messages.UpdateDialogFilter',
            { id, filter },
            { mutation: true },
          )) !== true
        )
          throw protocolError('Telegram did not confirm folder creation');
        return { success: true, folderId: `folder:${id}`, title };
      },
    );
  }

  async function logout() {
    const me = await getMe();
    return mutation(
      'logout',
      [me],
      {
        effect:
          'Revoke this Telegram authorization server-side, then remove' +
          ' its keyring/gopass credential and local reference. Other' +
          ' Telegram devices are not logged out.',
      },
      async () => {
        const result = await call<{ _: string }>(
          'auth.LogOut',
          {},
          { mutation: true },
        );
        if (result?._ !== 'auth.LoggedOut')
          throw protocolError('Telegram did not confirm server-side logout');
        return { revoked: true, accountId: peerKey(me) };
      },
    );
  }

  function folderPeerKey(peer: Peer) {
    return peer._ === 'InputPeerSelf' ? peerKey(accountUser) : peerKey(peer);
  }
  async function groupUser(group: Entity, identifier: string) {
    const numeric = parsePeerId(identifier);
    if (!numeric) return resolvePeer(identifier);
    if (numeric.kind !== 'user')
      throw securityError(
        'Administrative target must be a user, not a group/channel',
      );
    const usable = () => {
      const entity = entities.get(numeric.key);
      return (
        entity?._ === 'User' &&
        !entity.min &&
        !entity.deleted &&
        (entity.self || typeof entity.accessHash === 'bigint')
      );
    };
    if (!usable()) await getAllDialogs();
    if (!usable()) {
      if (group._ === 'Chat') {
        const result = await call<FullChat>('messages.GetFullChat', {
          chatId: group.id,
        });
        if (
          !result.fullChat?.participants?.participants?.some(
            (participant) => participant.userId === numeric.id,
          )
        )
          throw securityError('User ID was not found in the group');
      } else {
        // Learn hashes from authenticated member responses, never guess a hash
        // or interpret a numeric ID as an attacker-controlled display name.
        for (let offset = 0; offset < 10_000 && !usable(); offset += 200) {
          const result = await call<Participants>('channels.GetParticipants', {
            channel: inputChannel(group),
            filter: { _: 'ChannelParticipantsRecent' },
            offset,
            limit: 200,
            hash: 0n,
          });
          if (!Array.isArray(result.participants))
            throw protocolError('Unexpected member discovery response');
          if (result.participants.length < 200) break;
        }
      }
    }
    const entity = entities.get(numeric.key);
    if (!usable())
      throw securityError(
        'User ID could not be resolved within bounded member' +
          ' discovery (10,000 members). Use an explicit @username if' +
          ' available.',
      );
    inputUser(entity!);
    return entity!;
  }

  return {
    entities,
    call,
    me: getMe,
    whoami,
    dialogs: listDialogs,
    allDialogs: getAllDialogs,
    resolve: resolvePeer,
    message: projectMessage,
    history: getHistory,
    read,
    downloadMedia,
    search,
    contact,
    chat: getChat,
    members,
    send,
    deleteMessage,
    mute,
    kick,
    promote,
    transferOwner,
    folders: listFolders,
    folder: getFolder,
    changeFolder,
    createFolder,
    logout,
  };
}

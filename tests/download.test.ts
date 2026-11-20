import test from 'node:test';
import assert from 'node:assert/strict';
import {
  mkdir,
  chmod,
  readFile,
  readdir,
  stat,
  symlink,
  writeFile,
} from 'node:fs/promises';
import { join } from 'node:path';
import { main, parseCommand } from '../src/cli.ts';
import {
  downloadDirectory,
  openPrivateFile,
  privateDirectory,
} from '../src/files.ts';
import { createTelegram, MAX_DOWNLOAD_MIB } from '../src/telegram.ts';
import { createMediaRpc, createRpcClient } from '../src/rpc.ts';
import { rpcError } from '../src/common.ts';
import { decode, encode } from '../src/tl.ts';
import {
  channel,
  fakeCredentials,
  fakeRpc,
  scratch,
  session,
  user,
  windows,
  publicWindowsRead,
} from './support.ts';

const partSize = 512 * 1024;
const photoBytes = Buffer.concat([
  Buffer.from([255, 216, 255]),
  Buffer.alloc(partSize + 13, 0x31),
]);
const png = Buffer.from('89504e470d0a1a0a0001020304050607', 'hex');
function ogg(packet: string) {
  const header = Buffer.alloc(28);
  header.write('OggS');
  header[5] = 2;
  header[26] = 1;
  header[27] = packet.length;
  return Buffer.concat([header, Buffer.from(packet, 'latin1')]);
}
const photo = (extra = {}) => ({
  _: 'MessageMediaPhoto',
  photo: {
    _: 'Photo',
    id: 15n,
    accessHash: 20n,
    fileReference: Buffer.from([1, 2, 3]),
    date: 100,
    dcId: 2,
    sizes: [
      { _: 'PhotoStrippedSize', type: 'i', bytes: Buffer.from([1]) },
      { _: 'PhotoSize', type: 'm', w: 320, h: 180, size: 1200 },
      {
        _: 'PhotoSizeProgressive',
        type: 'y',
        w: 1200,
        h: 800,
        sizes: [200, photoBytes.length],
      },
    ],
    ...extra,
  },
});
const document = (extra = {}) => ({
  _: 'MessageMediaDocument',
  document: {
    _: 'Document',
    id: 16n,
    accessHash: 21n,
    dcId: 2,
    fileReference: Buffer.from([4, 5, 6]),
    mimeType: 'image/png',
    size: BigInt(png.length),
    attributes: [
      { _: 'DocumentAttributeFilename', fileName: '../../evil.svg' },
    ],
    ...extra,
  },
});
const message = (extra = {}) => ({
  _: 'Message',
  id: 77,
  date: 100,
  peerId: { _: 'PeerChannel', channelId: 9n },
  message: 'caption',
  media: photo(),
  ...extra,
});
function fixture(handler: Parameters<typeof fakeRpc>[0], entity = channel(9)) {
  const rpc = fakeRpc((name, args, opts, calls) => {
    if (name === 'contacts.ResolveUsername')
      return entity._ === 'Channel'
        ? { peer: { _: 'PeerChannel', channelId: entity.id }, chats: [entity] }
        : { peer: { _: 'PeerUser', userId: entity.id }, users: [entity] };
    return handler(name, args, opts, calls);
  });
  return {
    rpc,
    telegram: createTelegram(rpc, {
      mediaRpc: async (dc, account, transfer) => {
        assert.equal(dc, 2);
        assert.equal(account, 1n);
        return transfer(rpc);
      },
    }),
  };
}

test('CLI saves the largest photo in bounded parts', async (t) => {
  const directory = await scratch(t);
  const state = join(directory, 'state');
  const output = join(directory, 'images');
  const fake = fakeCredentials(state);
  await fake.store.create(session());
  const { rpc } = fixture((name, args) => {
    if (name === 'channels.GetMessages') {
      assert.deepEqual(args.id, [{ _: 'InputMessageID', id: 77 }]);
      assert.equal(args.channel.channelId, 9n);
      return { messages: [message()] };
    }
    assert.equal(name, 'upload.GetFile');
    assert.deepEqual(args.location, {
      _: 'InputPhotoFileLocation',
      id: 15n,
      accessHash: 20n,
      fileReference: Buffer.from([1, 2, 3]),
      thumbSize: 'y',
    });
    assert.equal(args.limit, partSize);
    assert.equal(args.cdnSupported, undefined);
    const offset = Number(args.offset);
    return decode(
      encode({
        _: 'upload.File',
        type: { _: 'storage.FileJpeg' },
        mtime: 100,
        bytes: photoBytes.subarray(offset, offset + partSize),
      }),
      'upload.File',
    );
  });
  let stdout = '';
  await main(
    [
      'download',
      '@group',
      '77',
      '-o',
      output,
      '--state-dir',
      state,
      '--json',
      '--quiet',
    ],
    {
      stdout: {
        write: (value: string) => {
          stdout += value;
        },
      },
      makeStore: () => fake.store,
      getDownloads: async () => assert.fail('Explicit output wins'),
      makeClient: () => ({
        ...rpc,
        async open() {},
        close() {},
      }),
    },
  );
  const { source, result } = JSON.parse(stdout);
  assert.equal(source, 'telegramctl');
  const path = join(output, 'channel-9-77.jpg');
  assert.equal(result.path, path);
  assert.equal(result.bytes, photoBytes.length);
  assert.equal(result.message.text, 'caption');
  assert.equal(result.message.media.type, 'photo');
  assert.equal(result.message.media.fileReference, undefined);
  assert.deepEqual(await readFile(path), photoBytes);
  if (!windows) {
    assert.equal((await stat(path)).mode & 0o777, 0o600);
    assert.equal((await stat(output)).mode & 0o777, 0o700);
  }
  assert.deepEqual(
    rpc.calls
      .filter(({ name }) => name === 'upload.GetFile')
      .map(({ args }) => args.offset),
    [0n, BigInt(partSize)],
  );
});

test('Default Downloads keeps its existing permissions', async (t) => {
  const root = await scratch(t),
    state = join(root, 'state'),
    output = join(root, 'Downloads'),
    fake = fakeCredentials(state);
  await fake.store.create(session());
  await privateDirectory(output);
  if (windows) publicWindowsRead(output, true);
  else await chmod(output, 0o755);
  const rpc = fakeRpc((name) => {
    if (name === 'messages.GetMessages') {
      return {
        messages: [
          message({
            peerId: { _: 'PeerUser', userId: 1n },
            media: document(),
          }),
        ],
      };
    }
    assert.equal(name, 'upload.GetFile');
    return { _: 'upload.File', bytes: png };
  });
  let stdout = '';
  const run = () =>
    main(
      ['download', 'self', '77', '--state-dir', state, '--json', '--quiet'],
      {
        stdout: {
          write: (value: string) => {
            stdout += value;
          },
        },
        makeStore: () => fake.store,
        makeClient: () => ({ ...rpc, open: async () => {}, close() {} }),
        getDownloads: async () => output,
      },
    );
  await run();
  const path = join(output, 'user-1-77.png');
  assert.equal(JSON.parse(stdout).result.path, path);
  assert.deepEqual(await readFile(path), png);
  await (await openPrivateFile(path, 1024)).close();
  if (!windows) assert.equal((await stat(output)).mode & 0o777, 0o755);
  await assert.rejects(run(), /refusing to replace/i);
  assert.deepEqual(await readdir(output), ['user-1-77.png']);
});

test(
  'Downloads rejects a writable shared destination',
  {
    skip: windows,
  },
  async (t) => {
    const output = join(await scratch(t), 'Downloads');
    await mkdir(output);
    await chmod(output, 0o1777);
    await assert.rejects(downloadDirectory(output), /not writable by others/);
    assert.equal((await stat(output)).mode & 0o7777, 0o1777);
    assert.deepEqual(await readdir(output), []);
  },
);

test('Image documents ignore the remote filename', async (t) => {
  const directory = await scratch(t);
  const { telegram } = fixture((name, args) => {
    if (name === 'messages.GetMessages')
      return {
        messages: [
          message({
            peerId: { _: 'PeerUser', userId: 55n },
            media: document(),
          }),
        ],
      };
    assert.equal(name, 'upload.GetFile');
    assert.equal(args.location._, 'InputDocumentFileLocation');
    assert.equal(args.location.thumbSize, '');
    return { _: 'upload.File', bytes: png };
  }, user(55));
  const result = await telegram.downloadMedia('@peer', 77, directory);
  assert.equal(result.path, join(directory, 'user-55-77.png'));
  assert.deepEqual(await readFile(result.path), png);
  await assert.rejects(
    telegram.downloadMedia('@peer', 77, directory),
    /refusing to replace/i,
  );
  assert.deepEqual(await readdir(directory), ['user-55-77.png']);
});

test('Downloads voice notes and ordinary audio', async (t) => {
  const cases: [string, string, Buffer, boolean?][] = [
    ['audio/ogg', 'ogg', ogg('OpusHead fixture'), true],
    ['application/octet-stream', 'ogg', ogg('OpusHead fixture'), true],
    ['application/ogg', 'ogg', ogg('\x01vorbis fixture')],
    ['audio/mpeg', 'mp3', Buffer.from('49443304000000000000', 'hex')],
    ['audio/mp3', 'mp3', Buffer.from('fffb9064', 'hex')],
    [
      'audio/mp4',
      'm4a',
      Buffer.from('00000018667479704d344120000000006d70343269736f6d', 'hex'),
    ],
    ['audio/wav', 'wav', Buffer.from('RIFF\0\0\0\0WAVE')],
    ['audio/flac', 'flac', Buffer.from('fLaC fixture')],
  ];
  for (const [mimeType, extension, bytes, voice] of cases) {
    const directory = await scratch(t);
    const media = document({
      mimeType,
      size: BigInt(bytes.length),
      attributes: [
        { _: 'DocumentAttributeAudio', duration: 5, voice },
        { _: 'DocumentAttributeFilename', fileName: '../../remote.mp3' },
      ],
    });
    const { telegram } = fixture((name, args, options) => {
      if (name === 'channels.GetMessages')
        return { messages: [message({ media })] };
      assert.equal(name, 'upload.GetFile');
      assert.equal(args.location._, 'InputDocumentFileLocation');
      assert.equal(args.location.thumbSize, '');
      assert.equal(options?.mutation, undefined);
      return { _: 'upload.File', bytes };
    });
    const result = await telegram.downloadMedia('@group', 77, directory);
    assert.equal(result.path, join(directory, `channel-9-77.${extension}`));
    assert.equal(result.message.media?.type, voice ? 'voice' : 'audio');
    assert.deepEqual(await readFile(result.path), bytes);
    if (!windows) assert.equal((await stat(result.path)).mode & 0o777, 0o600);
  }
});

test('Downloads an audio file sent as a generic attachment', async (t) => {
  const directory = await scratch(t);
  const bytes = Buffer.from('fLaC fixture');
  const media = document({
    mimeType: 'application/octet-stream',
    size: BigInt(bytes.length),
    attributes: [
      { _: 'DocumentAttributeFilename', fileName: '../../remote.FLAC' },
    ],
  });
  const { telegram } = fixture((name) =>
    name === 'channels.GetMessages'
      ? { messages: [message({ media })] }
      : { _: 'upload.File', bytes },
  );
  const result = await telegram.downloadMedia('@group', 77, directory);
  assert.equal(result.path, join(directory, 'channel-9-77.flac'));
  assert.deepEqual(await readFile(result.path), bytes);
});

test('Saves arbitrary attachments with safe local filenames', async (t) => {
  const cases = [
    { mime: 'application/pdf', ext: 'pdf', name: '../../report.PDF' },
    { mime: 'application/zip', ext: 'zip' },
    { mime: 'application/x-custom', ext: 'xyz', name: 'arbitrary.XYZ' },
    { mime: 'application/octet-stream', ext: 'bin', name: 'file.bad-ext' },
    { mime: 'video/mp4', ext: 'mp4', round: true },
  ];
  for (const { mime, ext, name, round } of cases) {
    const directory = await scratch(t);
    const bytes = Buffer.from([0, 1, 2, 3, 255]);
    const media = {
      ...document({
        mimeType: mime,
        size: BigInt(bytes.length),
        attributes: name
          ? [{ _: 'DocumentAttributeFilename', fileName: name }]
          : [],
      }),
      round,
    };
    const { telegram } = fixture((method, args) => {
      if (method === 'channels.GetMessages')
        return { messages: [message({ media })] };
      assert.equal(method, 'upload.GetFile');
      assert.equal(args.location._, 'InputDocumentFileLocation');
      assert.equal(args.location.thumbSize, '');
      return { _: 'upload.File', bytes };
    });
    const result = await telegram.downloadMedia('@group', 77, directory);
    const filename = `channel-9-77.${ext}`;
    assert.equal(result.path, join(directory, filename));
    assert.deepEqual(await readdir(directory), [filename]);
    assert.deepEqual(await readFile(result.path), bytes);
    if (!windows) assert.equal((await stat(result.path)).mode & 0o777, 0o600);
  }
});

test('Uses a neutral suffix for mislabeled or unknown media', async (t) => {
  for (const [mimeType, bytes] of [
    ['audio/mpeg', png],
    ['audio/wav', Buffer.from('fLaC fixture')],
    ['audio/ogg', ogg('\x80theora fixture')],
    ['image/png', Buffer.from('not an image')],
  ]) {
    const directory = await scratch(t);
    const media = {
      ...document({ mimeType, size: BigInt(bytes.length) }),
    };
    const { telegram } = fixture((name) =>
      name === 'channels.GetMessages'
        ? { messages: [message({ media })] }
        : { _: 'upload.File', bytes },
    );
    const result = await telegram.downloadMedia('@group', 77, directory);
    assert.equal(result.path, join(directory, 'channel-9-77.bin'));
    assert.deepEqual(await readFile(result.path), bytes);
  }
});

test('Denies wrong-chat, protected and oversized attachments', async (t) => {
  const directory = await scratch(t);
  for (const extra of [
    { id: 78 },
    { peerId: { _: 'PeerChannel', channelId: 4n } },
    { noforwards: true },
    { ttlPeriod: 45 },
    { media: { ...photo(), ttlSeconds: 5 } },
    { media: { _: 'MessageMediaWebPage' } },
    { media: document({ size: BigInt(MAX_DOWNLOAD_MIB * 1024 ** 2 + 1) }) },
  ]) {
    const { rpc, telegram } = fixture(() => ({ messages: [message(extra)] }));
    await assert.rejects(telegram.downloadMedia('@group', 77, directory));
    assert.ok(!rpc.calls.some(({ name }) => name === 'upload.GetFile'));
  }
  assert.deepEqual(await readdir(directory), []);
});

test('A bad chunk or CDN redirect leaves no partial file', async (t) => {
  const directory = await scratch(t);
  for (const badPart of [
    { _: 'upload.File', bytes: Buffer.alloc(0) },
    { _: 'upload.File', bytes: Buffer.alloc(1024) },
    { _: 'upload.FileCdnRedirect', dcId: 4 },
  ]) {
    const { telegram } = fixture((name, args) => {
      if (name === 'channels.GetMessages') return { messages: [message()] };
      return args.offset === 0n
        ? { _: 'upload.File', bytes: photoBytes.subarray(0, partSize) }
        : badPart;
    });
    await assert.rejects(
      telegram.downloadMedia('@group', 77, directory),
      /chunk length|CDN/,
    );
    assert.deepEqual(await readdir(directory), []);
  }
});

test('Refreshes a file reference without changing identity', async (t) => {
  for (const changed of [false, true]) {
    const directory = await scratch(t);
    let lookups = 0;
    const { telegram } = fixture((name, args) => {
      if (name === 'channels.GetMessages') {
        const media = photo({
          id: changed && lookups > 0 ? 30n : 15n,
          fileReference: Buffer.from([++lookups]),
        });
        return { messages: [message({ media })] };
      }
      const offset = Number(args.offset);
      if (offset !== 0 && args.location.fileReference[0] === 1)
        throw rpcError(400, 'FILE_REFERENCE_EXPIRED');
      return {
        _: 'upload.File',
        bytes: photoBytes.subarray(offset, offset + partSize),
      };
    });
    const download = telegram.downloadMedia('@group', 77, directory);
    if (changed) {
      await assert.rejects(download, /media changed/i);
      assert.deepEqual(await readdir(directory), []);
    } else {
      assert.deepEqual(await readFile((await download).path), photoBytes);
    }
    assert.equal(lookups, 2);
  }
});

test('Does not overwrite a destination symlink', async (t) => {
  const directory = await scratch(t);
  const output = join(directory, 'images');
  await privateDirectory(output);
  const outside = join(directory, 'outside'),
    original = windows ? join(outside, 'original') : outside;
  if (windows) await mkdir(outside);
  await writeFile(original, 'original');
  await symlink(
    outside,
    join(output, 'channel-9-77.png'),
    windows ? 'junction' : 'file',
  );
  const { telegram } = fixture((name) =>
    name === 'channels.GetMessages'
      ? { messages: [message({ media: document() })] }
      : { _: 'upload.File', bytes: png },
  );
  await assert.rejects(
    telegram.downloadMedia('@group', 77, output),
    /refusing to replace/i,
  );
  assert.equal(await readFile(original, 'utf8'), 'original');
  assert.deepEqual(await readdir(output), ['channel-9-77.png']);
});

test('A second data center gets and revokes a fresh key', async () => {
  for (const userId of [1n, 2n]) {
    const token = Buffer.alloc(10, 17);
    const futureToken = Buffer.alloc(10, 23);
    const events = [];
    const source = fakeRpc((name, args, opts) => {
      assert.equal(name, 'auth.ExportAuthorization');
      assert.equal(opts?.mutation, true);
      assert.deepEqual(args, { dcId: 3 });
      return { _: 'auth.ExportedAuthorization', id: 50n, bytes: token };
    });
    const remote = fakeRpc((name, args, opts) => {
      events.push(name);
      assert.equal(opts?.mutation, true);
      if (name === 'DestroyAuthKey') return { _: 'DestroyAuthKeyOk' };
      assert.equal(name, 'auth.ImportAuthorization');
      assert.deepEqual(args.bytes, Buffer.alloc(10, 17));
      return {
        _: 'auth.Authorization',
        user: user(userId),
        futureAuthToken: futureToken,
      };
    });
    const original = session();
    const connect = createMediaRpc(
      source,
      original,
      (params, opts) => {
        assert.deepEqual(params, { apiId: original.apiId, dcId: 3 });
        assert.equal(opts?.ephemeral, true);
        return {
          ...remote,
          async open() {
            events.push('open');
          },
          close() {
            events.push('close');
          },
        };
      },
      assert.fail,
    );
    assert.equal(await connect(2, 1n, async (client) => client), source);
    await assert.rejects(connect(6, 1n, async () => assert.fail()));
    const transfer = connect(3, 1n, async () => {
      events.push('transfer');
    });
    if (userId === 1n) await transfer;
    else await assert.rejects(transfer, /different user/);
    assert.deepEqual(events, [
      'open',
      'auth.ImportAuthorization',
      ...(userId === 1n ? ['transfer'] : []),
      'DestroyAuthKey',
      'close',
    ]);
    assert.deepEqual(token, Buffer.alloc(10));
    assert.deepEqual(futureToken, Buffer.alloc(10));
    assert.deepEqual(original.authKey, Buffer.alloc(256, 7));
  }
});

test('Download requires a valid message ID but not a destination', () => {
  assert.equal(
    parseCommand(['download', 'self', '5']).values.output,
    undefined,
  );
  assert.throws(
    () => parseCommand(['download', 'self']),
    /Incorrect arguments/,
  );
  assert.throws(
    () => parseCommand(['download', 'self', 'bad', '--output', '/fake']),
    /positive integer/,
  );
  assert.throws(() => parseCommand(['download', 'self', '5', '--output=']));
  assert.throws(
    () => createRpcClient(session(), { ephemeral: true }),
    /must generate its own key/,
  );
});

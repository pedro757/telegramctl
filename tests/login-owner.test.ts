import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, mkdir, symlink } from 'node:fs/promises';
import { join } from 'node:path';
import { authenticate } from '../src/cli.ts';
import { atomicPrivateWrite, privateDirectory } from '../src/files.ts';
import { createTelegram, rememberEntity } from '../src/telegram.ts';
import {
  securityError,
  rpcError,
  ambiguousMutationError,
} from '../src/common.ts';
import { fromBE, toBE, sha256, modPow, DH_PRIME } from '../src/crypto.ts';
import { pbkdf2Sync } from 'node:crypto';
import { encode } from '../src/tl.ts';
import {
  scratch,
  session,
  user,
  channel,
  chat,
  fakeRpc,
  fakeCredentials,
  directoryLink,
} from './support.ts';

function srpInfo(password) {
  const salt1 = Buffer.from('fake salt 1'),
    salt2 = Buffer.from('fake salt 2'),
    p = fromBE(DH_PRIME),
    g = 3n;
  const h1 = sha256(salt1, password, salt1),
    h2 = sha256(salt2, h1, salt2),
    x = fromBE(
      sha256(salt2, pbkdf2Sync(h2, salt1, 100_000, 64, 'sha512'), salt2),
    );
  const k = fromBE(sha256(DH_PRIME, toBE(g, 256))),
    B = (k * modPow(g, x, p) + modPow(g, 987654321123456789n, p)) % p;
  return {
    hasPassword: true,
    currentAlgo: {
      _: 'PasswordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow',
      salt1,
      salt2,
      p: DH_PRIME,
      g: 3,
    },
    srp_B: toBE(B, 256),
    srpId: 5n,
  };
}
test(
  'Interactive login follows DC migration and stores' +
    ' credentials only in the selected manager',
  async (t) => {
    const root = await scratch(t),
      directory = join(root, 'state'),
      clients = [],
      buffers = [],
      calls = [];
    const fake = fakeCredentials(directory);
    const options = {
      store: fake.store,
      ask: async () => '12345',
      askSecret: async (question) => {
        const value = Buffer.from(
          question.includes('API hash')
            ? session().apiHash
            : question.includes('Phone')
              ? '+12345678901'
              : '12345',
        );
        buffers.push(value);
        return value;
      },
      makeClient(data) {
        const client = {
          data,
          closed: false,
          async open() {},
          close() {
            client.closed = true;
          },
          exportSession: () => ({ ...session(), dcId: data.dcId }),
          async invoke(name, args, mutation) {
            encode({ ...args, _: name });
            calls.push({ name, args, mutation });
            if (name === 'auth.SendCode' && data.dcId === 2)
              throw rpcError(303, 'PHONE_MIGRATE_4');
            if (name === 'auth.SendCode')
              return {
                _: 'auth.SentCode',
                type: { _: 'auth.SentCodeTypeApp' },
                phoneCodeHash: 'fake-code-hash',
              };
            if (name === 'auth.SignIn')
              return { _: 'auth.Authorization', user: user(1, { self: true }) };
            throw new Error(name);
          },
        };
        clients.push(client);
        return client;
      },
    };
    const result = await authenticate(
      directory,
      {},
      () => {},
      () => {},
      options,
    );
    assert.equal(result.authenticated, true);
    assert.equal(result.dcId, 4);
    assert.equal(clients.length, 2);
    assert.ok(clients.every((client) => client.closed));
    assert.ok(buffers.every((buffer) => buffer.every((byte) => byte === 0)));
    const payload = await fake.store.load();
    assert.equal(payload.dcId, 4);
    payload.authKey.fill(0);
    const reference = await readFile(join(directory, 'session.json'), 'utf8');
    assert.ok(!reference.includes(session().apiHash));
    assert.ok(!reference.includes('authKey'));
    assert.ok(calls.every((call) => call.mutation.mutation));
  },
);
test(
  'Login performs 2FA through the hidden callback and uses an' +
    ' SRP proof, never the plaintext password as an RPC argument',
  async (t) => {
    const root = await scratch(t),
      directory = join(root, 'state'),
      password = Buffer.from(' fake 2FA password '),
      info = srpInfo(password),
      calls = [],
      secretQuestions = [];
    await authenticate(
      directory,
      {},
      () => {},
      () => {},
      {
        store: fakeCredentials(directory).store,
        ask: async () => '12345',
        askSecret: async (question) => {
          secretQuestions.push(question);
          return Buffer.from(
            question.includes('API hash')
              ? session().apiHash
              : question.includes('Phone')
                ? '+12345678901'
                : question.includes('2FA')
                  ? password
                  : '12345',
          );
        },
        makeClient(data) {
          return {
            async open() {},
            close() {},
            exportSession: () => ({ ...session(), dcId: data.dcId }),
            async invoke(name, args) {
              encode({ ...args, _: name });
              calls.push({ name, args });
              if (name === 'auth.SendCode')
                return {
                  _: 'auth.SentCode',
                  type: { _: 'auth.SentCodeTypeApp' },
                  phoneCodeHash: 'fake',
                };
              if (name === 'auth.SignIn')
                throw rpcError(401, 'SESSION_PASSWORD_NEEDED');
              if (name === 'account.GetPassword') return info;
              if (name === 'auth.CheckPassword') {
                assert.equal(args.password._, 'InputCheckPasswordSRP');
                assert.equal(args.password.M1.length, 32);
                return { _: 'auth.Authorization', user: user(1) };
              }
              throw new Error(name);
            },
          };
        },
      },
    );
    assert.ok(secretQuestions.some((question) => question.includes('2FA')));
    assert.ok(
      !JSON.stringify(calls, (_, value) =>
        typeof value === 'bigint' ? value.toString() : value,
      ).includes(password.toString()),
    );
  },
);
test(
  'Invalid local setup fields retry individually without losing' +
    ' earlier entries',
  async (t) => {
    const directory = await scratch(t),
      answers = ['not-an-id', '12345'],
      reviews = [],
      buffers = [],
      prompts = { hash: 0, phone: 0, code: 0 };
    const rpc = fakeRpc((name) => {
      if (name === 'auth.SendCode')
        return { _: 'auth.SentCode', phoneCodeHash: 'same-delivery' };
      if (name === 'auth.SignIn')
        return { _: 'auth.Authorization', user: user(1) };
      throw new Error(name);
    });
    const result = await authenticate(
      directory,
      {},
      () => {},
      () => {},
      {
        store: fakeCredentials(directory).store,
        ask: async (question, { review }) => {
          reviews.push(review);
          assert.ok(answers.length);
          return answers.shift();
        },
        askSecret: async (question, { review }) => {
          reviews.push(review);
          let value;
          if (question.includes('API hash'))
            value = ++prompts.hash === 1 ? 'bad hash' : session().apiHash;
          else if (question.includes('Phone'))
            value = ++prompts.phone === 1 ? '123' : '+12345678901';
          else {
            prompts.code++;
            value = '12345';
          }
          const buffer = Buffer.from(value);
          buffers.push(buffer);
          return buffer;
        },
        makeClient: () => ({
          ...rpc,
          async open() {},
          close() {},
          exportSession: session,
        }),
      },
    );
    assert.equal(result.authenticated, true);
    assert.equal(answers.length, 0);
    assert.deepEqual(prompts, { hash: 2, phone: 2, code: 1 });
    assert.ok(reviews.some((review) => review?.includes('Invalid API ID')));
    assert.ok(
      reviews.some((review) => review?.includes('Invalid API hash format')),
    );
    assert.ok(
      reviews.some((review) => review?.includes('Invalid phone format')),
    );
    assert.equal(
      rpc.calls.filter((call) => call.name === 'auth.SendCode').length,
      1,
    );
    assert.ok(buffers.every((buffer) => buffer.every((byte) => byte === 0)));
  },
);
test(
  'A locally invalid or server-rejected login code retries the' +
    ' existing delivery only',
  async (t) => {
    const directory = await scratch(t),
      inputs = ['not digits', '11111', '12345'],
      reviews = [],
      buffers = [];
    let submitted = 0;
    const rpc = fakeRpc((name, args) => {
      if (name === 'auth.SendCode')
        return { _: 'auth.SentCode', phoneCodeHash: 'same-delivery' };
      if (name === 'auth.SignIn') {
        assert.equal(args.phoneCodeHash, 'same-delivery');
        submitted++;
        if (submitted === 1) throw rpcError(400, 'PHONE_CODE_INVALID');
        return { _: 'auth.Authorization', user: user(1) };
      }
      throw new Error(name);
    });
    const result = await authenticate(
      directory,
      {},
      () => {},
      () => {},
      {
        store: fakeCredentials(directory).store,
        ask: async () => '12345',
        askSecret: async (question, { review }) => {
          reviews.push(review);
          const value = Buffer.from(
            question.includes('API hash')
              ? session().apiHash
              : question.includes('Phone')
                ? '+12345678901'
                : inputs.shift(),
          );
          buffers.push(value);
          return value;
        },
        makeClient: () => ({
          ...rpc,
          async open() {},
          close() {},
          exportSession: session,
        }),
      },
    );
    assert.equal(result.authenticated, true);
    assert.equal(submitted, 2);
    assert.equal(inputs.length, 0);
    assert.ok(
      reviews.some((review) => review?.includes('Invalid login code format')),
    );
    assert.ok(
      reviews.some((review) =>
        review?.includes('no new code has been requested'),
      ),
    );
    assert.equal(
      rpc.calls.filter((call) => call.name === 'auth.SendCode').length,
      1,
    );
    assert.ok(buffers.every((buffer) => buffer.every((byte) => byte === 0)));
  },
);
test(
  'Rejected 2FA retries only the password, fetches fresh SRP' +
    ' parameters and preserves the setup',
  async (t) => {
    const directory = await scratch(t),
      info = srpInfo(Buffer.from('correct fake password')),
      questions = [],
      reviews = [],
      passwords = [];
    let parameters = 0,
      proofs = 0;
    const rpc = fakeRpc((name, args) => {
      if (name === 'auth.SendCode')
        return { _: 'auth.SentCode', phoneCodeHash: 'same-delivery' };
      if (name === 'auth.SignIn')
        throw rpcError(401, 'SESSION_PASSWORD_NEEDED');
      if (name === 'account.GetPassword')
        return { ...info, srpId: BigInt(++parameters) };
      if (name === 'auth.CheckPassword') {
        proofs++;
        assert.equal(args.password.srpId, BigInt(proofs));
        if (proofs === 1) throw rpcError(400, 'PASSWORD_HASH_INVALID');
        return { _: 'auth.Authorization', user: user(1) };
      }
      throw new Error(name);
    });
    await authenticate(
      directory,
      {},
      () => {},
      () => {},
      {
        store: fakeCredentials(directory).store,
        ask: async () => '12345',
        askSecret: async (question, { review }) => {
          questions.push(question);
          reviews.push(review);
          if (question.includes('2FA')) {
            const value = Buffer.from(
              passwords.length
                ? 'correct fake password'
                : 'wrong fake password',
            );
            passwords.push(value);
            return value;
          }
          return Buffer.from(
            question.includes('API hash')
              ? session().apiHash
              : question.includes('Phone')
                ? '+12345678901'
                : '12345',
          );
        },
        makeClient: () => ({
          ...rpc,
          async open() {},
          close() {},
          exportSession: session,
        }),
      },
    );
    assert.equal(parameters, 2);
    assert.equal(proofs, 2);
    assert.equal(
      questions.filter((question) => question.includes('API hash')).length,
      1,
    );
    assert.equal(
      questions.filter((question) => question.includes('Phone')).length,
      1,
    );
    assert.equal(
      questions.filter((question) => question.includes('login code')).length,
      1,
    );
    assert.equal(
      rpc.calls.filter((call) => call.name === 'auth.SendCode').length,
      1,
    );
    assert.ok(
      reviews.some((review) =>
        review?.includes('earlier setup entries are still retained'),
      ),
    );
    assert.ok(
      passwords.every((password) => password.every((byte) => byte === 0)),
    );
  },
);
test(
  'Expired codes, rate limits, integrity errors and ambiguous' +
    ' submissions do not trigger login retries',
  async (t) => {
    for (const failure of [
      rpcError(400, 'PHONE_CODE_EXPIRED'),
      rpcError(420, 'FLOOD_WAIT_90'),
      securityError('Fake integrity failure'),
      ambiguousMutationError(),
    ]) {
      const directory = await scratch(t),
        buffers = [];
      let closed = false;
      const rpc = fakeRpc((name) => {
        if (name === 'auth.SendCode')
          return { _: 'auth.SentCode', phoneCodeHash: 'same-delivery' };
        if (name === 'auth.SignIn') throw failure;
        throw new Error(name);
      });
      await assert.rejects(
        authenticate(
          directory,
          {},
          () => {},
          () => {},
          {
            store: fakeCredentials(directory).store,
            ask: async () => '12345',
            askSecret: async (question) => {
              const value = Buffer.from(
                question.includes('API hash')
                  ? session().apiHash
                  : question.includes('Phone')
                    ? '+12345678901'
                    : '12345',
              );
              buffers.push(value);
              return value;
            },
            makeClient: () => ({
              ...rpc,
              async open() {},
              close() {
                closed = true;
              },
              exportSession: session,
            }),
          },
        ),
        (error) => error === failure,
      );
      assert.equal(
        rpc.calls.filter((call) => call.name === 'auth.SendCode').length,
        1,
      );
      assert.equal(
        rpc.calls.filter((call) => call.name === 'auth.SignIn').length,
        1,
      );
      assert.equal(closed, true);
      assert.ok(buffers.every((buffer) => buffer.every((byte) => byte === 0)));
    }
  },
);
test(
  'Failed credential reference persistence revokes the new' +
    ' authorization and does not overwrite another file',
  async (t) => {
    const root = await scratch(t),
      directory = join(root, 'state');
    let revocations = 0;
    await assert.rejects(
      authenticate(
        directory,
        {},
        () => {},
        () => {},
        {
          store: fakeCredentials(directory).store,
          ask: async () => '12345',
          askSecret: async (question) =>
            Buffer.from(
              question.includes('API hash')
                ? session().apiHash
                : question.includes('Phone')
                  ? '+12345678901'
                  : '12345',
            ),
          makeClient(data) {
            return {
              async open() {},
              close() {},
              exportSession: () => ({ ...session(), dcId: data.dcId }),
              async invoke(name) {
                if (name === 'auth.SendCode')
                  return { _: 'auth.SentCode', phoneCodeHash: 'fake' };
                if (name === 'auth.SignIn') {
                  await atomicPrivateWrite(
                    directory,
                    'session.json',
                    'PREEXISTING_VALUE',
                  );
                  return { _: 'auth.Authorization', user: user(1) };
                }
                if (name === 'auth.LogOut') {
                  revocations++;
                  return { _: 'auth.LoggedOut' };
                }
                throw new Error(name);
              },
            };
          },
        },
      ),
      /already configured/,
    );
    assert.equal(revocations, 1);
    assert.equal(
      await readFile(join(directory, 'session.json'), 'utf8'),
      'PREEXISTING_VALUE',
    );
  },
);
test(
  'Login with an accepted lexical state path does not revoke' +
    ' successfully stored credentials',
  async (t) => {
    const root = await scratch(t),
      checked = await privateDirectory(join(root, 'checked')),
      actual = await privateDirectory(join(root, 'actual'));
    await mkdir(join(actual, 'nested'), { mode: 0o700 });
    await symlink(
      join(actual, 'nested'),
      join(checked, 'alias'),
      directoryLink,
    );
    const directory = `${checked}/alias/../state`;
    let revocations = 0;
    const fake = fakeCredentials(directory);
    const result = await authenticate(
      directory,
      {},
      () => {},
      () => {},
      {
        store: fake.store,
        ask: async () => '12345',
        askSecret: async (question) =>
          Buffer.from(
            question.includes('API hash')
              ? session().apiHash
              : question.includes('Phone')
                ? '+12345678901'
                : '12345',
          ),
        makeClient() {
          return {
            async open() {},
            close() {},
            exportSession: () => session(),
            async invoke(name) {
              if (name === 'auth.SendCode')
                return { _: 'auth.SentCode', phoneCodeHash: 'fake' };
              if (name === 'auth.SignIn')
                return { _: 'auth.Authorization', user: user(1) };
              if (name === 'auth.LogOut') {
                revocations++;
                return { _: 'auth.LoggedOut' };
              }
              throw new Error(name);
            },
          };
        },
      },
    );
    assert.equal(result.authenticated, true);
    assert.equal(revocations, 0);
    const loaded = await fake.store.load();
    assert.equal(loaded.apiId, 12345);
    loaded.authKey.fill(0);
    await fake.store.remove();
  },
);
test(
  'Direct ownership transfer retains stable IDs, requested' +
    ' auditing and hidden SRP input',
  async () => {
    const owner = user(1, { self: true }),
      target = user(2),
      group = channel(10, { creator: true });
    const password = Buffer.from(' fake transfer password '),
      info = srpInfo(password),
      audits = [];
    const rpc = fakeRpc((name, args, options) => {
      if (name === 'channels.GetParticipant')
        return { participant: { _: 'ChannelParticipant', userId: 2n } };
      if (name === 'account.GetPassword') return info;
      if (name === 'messages.EditChatCreator') {
        assert.equal(args.peer.channelId, 10n);
        assert.equal(args.userId.userId, 2n);
        assert.equal(args.password._, 'InputCheckPasswordSRP');
        assert.equal(options.mutation, true);
        return { _: 'UpdatesTooLong' };
      }
      throw new Error(name);
    });
    const telegram = createTelegram(rpc, {
      audit: async (entry) => {
        audits.push(entry);
        group.title = 'renamed during audit';
      },
      secret: async () => password,
    });
    for (const entity of [owner, target, group])
      rememberEntity(telegram.entities, entity);
    assert.equal(
      (await telegram.transferOwner('channel:10', 'user:2')).success,
      true,
    );
    assert.equal(audits[0].account, 'user:1');
    assert.deepEqual(audits[0].peers, ['channel:10', 'user:2']);
    assert.deepEqual(
      audits.map((entry) => entry.status),
      ['requested', 'succeeded'],
    );
    assert.ok(password.every((byte) => byte === 0));
  },
);
test(
  'Ownership preconditions reject nonmembers/nonowners before' +
    ' prompting for a secret',
  async () => {
    let secrets = 0;
    const rpc = fakeRpc((name) => {
      if (name === 'messages.GetFullChat')
        return { fullChat: { participants: { participants: [] } } };
      throw new Error(name);
    });
    const telegram = createTelegram(rpc, {
      secret: async () => {
        secrets++;
        return Buffer.from('fake');
      },
    });
    rememberEntity(telegram.entities, chat(3, { creator: true }));
    rememberEntity(telegram.entities, user(2));
    await assert.rejects(
      telegram.transferOwner('chat:3', 'user:2'),
      /already be a member/,
    );
    rememberEntity(telegram.entities, channel(4, { creator: false }));
    await assert.rejects(
      telegram.transferOwner('channel:4', 'user:2'),
      /requires an owned/,
    );
    assert.equal(secrets, 0);
    assert.ok(
      !rpc.calls.some((call) => call.name === 'messages.EditChatCreator'),
    );
  },
);
test(
  'Basic group ownership uses InputPeerChat with the current' +
    ' transfer method',
  async () => {
    const raw = Buffer.from(' fake basic-group password '),
      info = srpInfo(raw);
    const rpc = fakeRpc((name, args) => {
      if (name === 'messages.GetFullChat')
        return {
          fullChat: { participants: { participants: [{ userId: 2n }] } },
        };
      if (name === 'account.GetPassword') return info;
      assert.equal(name, 'messages.EditChatCreator');
      assert.equal(args.peer._, 'InputPeerChat');
      assert.equal(args.peer.chatId, 3n);
      return { _: 'UpdatesTooLong' };
    });
    const telegram = createTelegram(rpc, { secret: async () => raw });
    rememberEntity(telegram.entities, chat(3, { creator: true }));
    rememberEntity(telegram.entities, user(2));
    assert.equal(
      (await telegram.transferOwner('chat:3', 'user:2')).success,
      true,
    );
  },
);
test('Direct ownership transfer requires Telegram 2FA input', async () => {
  const rpc = fakeRpc((name) => {
    if (name === 'channels.GetParticipant')
      return { participant: { _: 'ChannelParticipant', userId: 2n } };
    if (name === 'account.GetPassword') return {};
    throw new Error('Ownership must not change without 2FA');
  });
  const telegram = createTelegram(rpc);
  rememberEntity(telegram.entities, channel(10, { creator: true }));
  rememberEntity(telegram.entities, user(2));
  await assert.rejects(
    telegram.transferOwner('channel:10', 'user:2'),
    /Interactive 2FA is required/,
  );
  assert.ok(
    !rpc.calls.some((call) => call.name === 'messages.EditChatCreator'),
  );
});
test(
  'Credential deletion refuses a replacement made while an' +
    ' operation/approval was pending',
  async (t) => {
    const directory = await scratch(t),
      fake = fakeCredentials(directory);
    await fake.store.create(session());
    const expectedFingerprint = await fake.store.fingerprint();
    const key = [...fake.records.keys()][0];
    fake.records.set(
      key,
      Buffer.from(
        JSON.stringify({
          ...JSON.parse(fake.records.get(key).toString()),
          apiId: 54321,
        }),
      ),
    );
    await assert.rejects(
      fake.store.remove({ expectedFingerprint }),
      /stored session changed/,
    );
    const loaded = await fake.store.load();
    assert.equal(loaded.apiId, 54321);
    loaded.authKey.fill(0);
  },
);

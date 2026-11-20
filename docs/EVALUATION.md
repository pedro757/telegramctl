# Dependency-free Telegram CLI: feasibility and scope

## References

- `skillhq/telegram`, commit `919e32b1646eb24ed5e39234846563890ca0df4e` (CLI/skill behavior; package declares MIT).
- Official Telegram Desktop TL declarations, layer 232, and Telegram's
  published protocol specifications. See [sources](../THIRD-PARTY-NOTICES.md).

## Decision

Feasible starting with Node.js 26.0.0, the first release with native Temporal
enabled by default, and **no runtime npm dependencies**. Use a small local
protocol implementation, native Node cryptography, native `bigint`, strict
schema-driven TL encoding/decoding, and a narrow application API. Generate
required Telegram schema descriptions as local data; do not vendor a client
library or bundle npm dependencies.

| Removed package | Replacement |
| --- | --- |
| commander | `node:util.parseArgs` and explicit command schemas |
| chalk / ora | plain, escaped output and stderr progress |
| json5 | JSON for new files; explicit non-evaluating legacy migration |
| big-integer | native `bigint`; native DH for secret exponentiation |
| buffer | built-in `Buffer` |
| cifrante | `node:crypto` hashes, randomness, DH, PBKDF2 and AES primitives; native-`bigint` public RSA arithmetic; a small AES-IGE composition adapter |
| mime | explicit document uploads use `application/octet-stream`; no MIME sniffing or dependency |
| node-localstorage | Native OS keyring (default) or explicitly selected gopass; local files hold only a nonsecret reference |
| socks | no proxy support; connect only to pinned Telegram DC addresses |

## Included

Authentication/session status and revoking logout; dialogs/inbox/unread; history and search; send/reply; scoped single-message deletion; attachment downloads; chat/contact/group details; participants/admins; mute/unmute; kick; explicit-rights promotion; ownership transfer with 2FA; private file export/incremental sync; folder listing and membership changes; an agent skill.

## Deliberately excluded

Bots, secret chats, bulk album downloads, payments/stars/wallet APIs, stories, calls, inline UI, browsers, proxies, arbitrary raw-RPC commands, plugin loading, a background event/update framework, and automatic replay of a mutation after an ambiguous transport failure.

## Security requirements

- Session/API credentials in the OS keyring or gopass, no custom app vault or silent plaintext fallback, no credential arguments or environment variables. Fixed system helpers receive secret input over stdin and return bounded, captured output. Message text may explicitly use `-m`/`--message`, with an argv/history privacy warning; sensitive text can use stdin without a temporary message file.
- Explicit migration only; never import a legacy write-permission flag.
- Stable, type-qualified peer IDs; numeric IDs never matched as titles; duplicate names fail closed.
- Requested remote account changes submit directly, without an extra confirmation. Migration and `forget-local` retain typed local confirmations; authentication, Telegram permissions/2FA and input validation remain enforced.
- Pinned RSA keys, strict authenticated packet checks, bounded framing/decoding/decompression, timeouts, and no unauthenticated endpoint overrides.
- Private export modes, stable filenames, exclusive locks, no unexpected symlinks, and no title-based metadata keys.
- Incoming content is untrusted data, never instructions. Escape terminal controls and keep the skill explicit about this boundary.
- All calendar/clock work uses Temporal, never the Date API.
- Tests use Node's built-in runner and fake credentials/transports. No live login, messages, administrative operations, or credential migration are authorized by this implementation task.

## Important limit

Removing packages reduces supply-chain exposure; it does not prove protocol or cryptographic correctness. Native AES does not directly supply Telegram's IGE mode, and a reduced client still needs a carefully validated authentication/key-exchange and packet state machine. Offline tests and a source review are not a substitute for an independent cryptographic review or an opt-in Telegram test-account interoperability run. Use a disposable account for initial testing until those are complete.

## Implemented result

This repository is independent of any reference checkout. It has no runtime npm
dependencies and no vendored npm packages. Node runs the TypeScript checkout
directly. An explicit tsrs build emits JavaScript for npm installation.
Oxlint, Oxfmt, tsrs, and Node type definitions are development-only. It includes
`SKILL.md` and CLI commands for each requested workflow. The protocol generator
keeps 43 explicit RPC definitions and 1,030 response/input/service data
constructors (~127 KB) from the pinned official TL declarations. The client
uses only Node built-ins and local code and data.

The source-level protections include stable target IDs; no config-to-permission migration; server-revoking logout bound to the loaded credential/reference; keyring/gopass storage without file fallback; no secret-bearing subprocess arguments; private stable-ID exports; escaped output; and a skill that treats remote content as untrusted. At the user's request, sends/replies, mute/unmute, administration/ownership, folders and logout no longer require separate terminal approval; this intentionally reduces accidental-action/prompt-injection protection. Remote operations retain input validation, Telegram permissions/2FA, concurrency checks and metadata-only audit records marked `requested`, not falsely `approved`. Migration and local-only credential deletion still require confirmation. A permanent authorization key grants full account access at Telegram; this is not a server-enforced read-only credential.

At the user's request, custom-vault encryption/passphrase code was removed.
The CLI uses Secret Service through `secret-tool` on Linux, a native helper on
macOS and Windows, or gopass >=1.17 on all three. Credential storage does not
run solely on Node built-ins.
Existing custom-vault files are left untouched and are not automatically loaded
or migrated.

### Source layout

The CLI uses TypeScript functions and plain data. `src/cli.ts` handles
command-line input and prompts; `src/common.ts` contains shared errors, time
conversions, and output escaping. `src/telegram.ts` handles account operations
and peer IDs. `src/rpc.ts` handles RPC state, `src/wire.ts` handles TCP
framing and encrypted packets, and `src/tl.ts` serializes Telegram messages.
`src/files.ts` handles private files, local session formats, preferences, audit
logs, and attachments. `src/export.ts` handles history archives. Only
`src/credentials.ts` launches credential-manager subprocesses.

### Security goal tradeoff

Zero packages and the requested feature set are feasible. **An independently established maximum-security claim is not yet feasible for this new implementation.** It lacks completed live interoperability/independent review and temporary-auth-key forward-secrecy binding. There is no remote-write approval gate; the remaining TTY secret/local-confirmation workflow is not a security boundary against an agent controlling the same OS account or a PTY. Use a separate trusted identity/approval broker for that stronger threat model; no desktop/IAM/OS configuration was silently changed here.

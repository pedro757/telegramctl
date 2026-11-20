# Security model and release status

## Verification status

This is a new, dependency-free Telegram client for Node.js 26.0.0 and newer, not a claim of “maximum” or proven security. Its offline tests pass, but **no independent audit or live Telegram interoperability run has been completed**. In particular, a complete real key exchange/login and destructive administration have not been tested against Telegram. Do not use a primary account or a valuable group/channel until independent review and disposable-account testing are complete.

Removing third-party packages reduces the npm supply-chain surface, but replaces mature client behavior with code that can contain new protocol/state/cryptographic bugs. **Fewer dependencies is not evidence of stronger cryptography.**

## Threats addressed

- Third-party package lifecycle scripts, dependency substitutions and plugin
  loading: no runtime npm packages or dynamic code evaluation. Use
  `npm ci --ignore-scripts` to install the pinned development tools. Only the
  native-helper adapter spawns subprocesses, without a shell. It uses absolute
  system/package paths or the trusted absolute `TELEGRAMCTL_GOPASS_PATH` chosen
  by the operator; it does not look up executables on `PATH` at runtime.
- Accidental disclosure of stored authorization keys/API hashes: Linux Secret
  Service, macOS Keychain, Windows Credential Manager, or explicitly selected
  gopass; no custom vault, plaintext credential file, or silent fallback.
- Credential argv/environment/terminal echo exposure: hidden controlling-terminal setup/2FA input; helper payloads travel over stdin, never command arguments/environment. Captured secret stdout is bounded, validated, cleared where practical, and never printed; helper stderr is discarded, not exposed through exceptions.
- Message argv exposure is an explicit tradeoff: `send`/`reply -m` or `--message` accepts ordinary text directly, which can appear in shell history, process listings and agent/tool logs. Prefer stdin, an existing message descriptor or the hidden prompt for sensitive content. Stdin removes the body from this CLI's argv, not from any logging performed by its launcher. Message input needs no temporary file. Credential arguments remain unsupported.
- Attachment disclosure: send only a local file that the user has explicitly chosen for the intended recipient. The file bytes, basename and optional caption go to Telegram, but the full source path does not. The path is still a command-line argument. Only nonempty regular files up to 100 MiB are opened; symlinks and special files are rejected. Reads use one pinned descriptor in 512 KiB parts, without a temporary copy. Changes detected by descriptor size/mtime/ctime checks stop publication; this is not protection against a hostile filesystem. Failed uploads may leave temporary parts on Telegram, even when no message was submitted. The required small-file MD5 checksum is not used for security.
- Wrong-recipient actions through mutable titles or numeric-title spoofing: type-qualified IDs, numeric-first parsing, unique exact names and stable resolved inputs. There is no extra sender/target confirmation before remote operations.
- Unexpected preference-based permissions: preferences are nonsecret JSON with a strict two-key schema; permission flags are neither loaded nor migrated. Remote account changes are intentionally direct, not read-only by default; no local write-permission flag is required.
- Message deletion requires an explicit scope and checks that the exact
  message ID belongs to the selected chat before submitting the mutation.
  Channel and supergroup deletion requires `--for-everyone`. A deletion with
  an uncertain outcome is not replayed automatically.
- False revocation/logout: server-side logout confirmation, error reporting, verified manager-entry removal, and fingerprint binding to the originally loaded reference/credential.
- Network message tampering/replay/resource abuse: pinned server RSA keys/DC endpoints, DH validation, message/session/auth-key checks, bounded framing/decompression/TL parsing and absolute I/O deadlines.
- Export leakage/corruption: private files, type-qualified filenames, authenticated-account-bound headers/metadata, exclusive locks, per-chat atomic replacements, validated resume data, no title/path-based filenames or trusted metadata cursors. Unbound legacy archives fail closed.
- Escape/control output attacks: escaped terminal controls/bidi, structured JSON, fenced Markdown. No automatic link opening or media download.
- Explicit attachment downloads bind the message to the selected chat, reject
  protected or disappearing media, and cap transfer size. Files are private,
  published only after transfer, and never overwritten or opened automatically.
  Linux/macOS Downloads directories may be readable by others, but must be
  owned by the current user and not writable by others. On Windows the
  directory must have a safe ACL and the file gets an explicit private ACL.
  The CLI checks recognized image and audio headers only to choose an extension;
  neither a header nor a filename means a file is safe to open. Cross-data-center
  downloads use a separate key; it is never saved locally, and the CLI warns if
  it cannot confirm removal.
- Mutation replay after uncertain delivery: no automatic reconnect/replay; outcome is explicitly unknown. Only explicit correlated protocol rejections have bounded retries.

## Not a boundary against an agent controlling your OS account

**Remote operations have no CLI approval gate.** The remaining controlling-terminal checks protect secret entry and local migration/deletion confirmations; they are not proof of a human or an OS sandbox. An agent able to modify code, set `NODE_OPTIONS`, inspect the process, or read an unlocked same-user keyring/gopass session can act with that session. Skill instructions are not an operating-system enforcement mechanism. Credential-manager access is not a server-enforced read-only Telegram capability.

For stronger isolation, keep the account/session and approval mechanism in a **separate trusted OS identity or external broker** that the agent cannot modify or impersonate. Grant only narrow, externally enforced capabilities. That broker, hardware-backed user presence, kernel sandboxing/network policy, and deployment configuration are **not implemented here**. Do not give an untrusted agent the decryption credential and then assume the CLI is a read-only sandbox.

## Cryptographic details and limits

- Native Node/OpenSSL supplies randomness, SHA-1/SHA-256, Telegram-required PBKDF2, AES and DH. Protocol-required SHA-1 is not used as a new application password KDF.
- Telegram's AES-IGE uses a small adapter around native AES-256-ECB; it is **not** hand-written AES. Independent OpenSSL IGE fixtures and native-RSA/SRP oracle tests cover it, not every protocol edge.
- Server RSA fingerprints are recomputed from pinned moduli. No server-offered unpinned key, arbitrary host, proxy, or config-supplied endpoint is accepted.
- The DH prime is a pinned 2048-bit safe prime; authorization-key DH permits only generators 3, 4 and 7, which satisfy the pinned prime's subgroup residue rules, and checks public-value margins. Password SRP has a separate parameter validator, retaining supported SRP generators without relaxing DH. Unknown primes are rejected rather than automatically extending trust.
- Secret modular exponentiation uses native DH. Some surrounding SRP arithmetic still uses JavaScript `bigint`; no blanket constant-time or side-channel-resistance guarantee is made.
- Authentication checks nonces, inner DH hash/padding, parameter validity and new-nonce confirmation. Successful full exchange against a real server remains unverified.
- Authenticated packet checks include key ID, message key, session ID, lengths/padding, server-ID parity, time window, duplicate/floor protection, container ordering and correlated salt/clock changes. Unknown constructors/flag bits fail closed.
- A stale saved offset can recover through a standalone authenticated error-16/17 notification for the active request ID **and sequence**, under a known/requested salt, with a correction bounded to one day and a consistent direction. Replay/session checks remain active; ordinary, compressed or container traffic cannot bypass freshness using this exception.
- This minimal client uses the permanent authorization key directly. **Temporary authorization-key binding and forward-secrecy key rotation are not implemented.** Compromise of the authorization key can compromise recorded traffic protected by that key.
- Credential encryption, unlocking and access policy belong to the OS keyring or gopass/GPG agent. This program implements no credential-encryption scheme or app passphrase. Verify the manager's configuration, lock policy, gopass recipients, Git hooks and backups yourself.
- JavaScript strings/BigInts, garbage collection, native crypto objects, swap, crash dumps, terminal recorders and process memory cannot be reliably zeroized or protected by this program. Buffers are cleared where practical; that is not a secure-memory guarantee.
- Cloud Telegram chats are not made end-to-end encrypted by this CLI. Secret chats are not supported.

## Storage and privacy

The selected manager contains the API ID/hash, authorization key, DC ID and salt/time state. Private `session.json` contains only a backend name, directory-profile hash and random entry ID; `config.json` only contains `version` and `defaultFormat`. The local reference is not a vault or credential file. Existing `session.enc.json` files and legacy plaintext configs are never automatically read, migrated or deleted.

Local references/preferences/exports use private regular files without hard
links. On Linux/macOS the CLI checks ownership, file modes, symlinks and
group/other-writable non-sticky parents. On macOS use locations without
extended ACLs that grant additional access; the POSIX checks do not audit
those grants. On Windows the helper rejects reparse
points, network shares, untrusted ownership and unsafe ACLs. It creates private
files and directories with explicit ACLs for the current user, SYSTEM and
Administrators; existing private files must be owned by the current user.
Windows administrators and system-level principals are outside this boundary.
New-file creation is exclusive; replacements publish a synced file via rename.
Directory-entry crash durability is not provided on Windows or where macOS
cannot sync a directory. Locks coordinate cooperating clients.

Manager entries use the canonical state-directory hash plus a random ID so new
setup does not overwrite an old entry. Reference creation follows read-back
verification. Manager writes and local metadata are not one atomic transaction:
a crash/helper/cleanup failure can leave an orphan entry or stale reference.
Do not blindly delete unrelated entries to recover.

The reference pins the chosen backend; locked/unavailable managers do not trigger a switch or plaintext fallback. Helper calls have a 120-second deadline and 32 KiB output cap; stored session reads are capped at 16 KiB. gopass fuzzy search, parsing, auto-sync and automatic clipboard copying are disabled; secret reads name only the selected entry. Deletion verification requests metadata scoped to that exact entry, never a store-wide secret search/export. Its encryption recipients, Git history/hooks and agent behavior remain the user's trust boundary. Deleting an entry cannot erase encrypted history/backups. Secret Service/GPG unlocking may still require the manager's trusted UI; no unlock password is collected by this app.

Logout binds deletion to the loaded reference/credential fingerprint and
verifies absence before removing the local reference. For the OS stores the
CLI checks the exact entry; for gopass it uses entry-scoped
`list --flat --limit 1` and its documented NotFound code 10. A failed gopass
`show` can wrap missing-entry and decryption errors alike and is not evidence
of absence. None of the adapters offers a transactional compare-and-swap
across lookup/deletion; non-cooperating manual edits can race that window.
Cooperating CLI processes use the same profile lock. Server-side Telegram
revocation remains necessary for leaked/copied sessions even after local deletion.

Node's filesystem APIs do not provide a complete portable `openat2`/directory-capability sandbox here. Path checks and `O_NOFOLLOW` are defense in depth, **not** protection against a hostile same-user process continuously swapping directory trees. Keep the repository/runtime, state and exports in trusted, private locations.

Exports contain plaintext private messages, independently of credential-manager encryption. They are deliberately created only by an export request. Audit logs contain timestamps, sender/target IDs, a plan digest and outcome—not content, names, API arguments or passwords. Plan digests can still permit guessing low-entropy plans from known metadata; keep logs private and set an intentional retention policy.

The app does not emit telemetry or contact analytics/services. Its own runtime networking goes to pinned Telegram DCs; the credential helper communicates with the local manager/GPG agent and may invoke user-configured hooks. Telegram sees the API calls/searches you request. The optional **explicit** schema-generation command can fetch one SHA-256-pinned GitHub file; normal commands never fetch updates.

## Read/write and AI content policy

Read methods do not invoke mark-read APIs, but returning private data to a model is itself a disclosure requiring user intent. Global searches, contact lookups and exports must stay within that intent.

Message text, titles, usernames, bios, folder names and exports are untrusted data. Escaping stops terminal/rendering controls; it does **not** solve semantic prompt injection. Neither a JSON envelope nor a file extension can prevent an LLM from following malicious text. The skill requires strict instruction/data separation and prohibits self-authorized writes, credential access and exfiltration. Strong enforcement belongs outside the model/CLI process.

Sending/replying, mute/unmute, administration (including ownership transfer), folder changes and logout intentionally have no extra CLI approval step. Supplying valid inputs submits the operation directly. Text supplied with `-m`/`--message`, stdin or a message descriptor works without a controlling terminal; ownership transfer still needs hidden Telegram 2FA input, and the credential manager may require unlocking. Inline messages are validated before credential access/networking; all message sources use the same content validation. The skill requires clear user intent for the account, exact targets, operation and content/rights; incoming Telegram content cannot authorize any action.

Removing confirmation reduces protection against accidental or agent-triggered account changes; it does not remove Telegram's server-side permissions or 2FA. Stable-ID resolution, input validation, metadata-only auditing, folder concurrency checks and ambiguous-outcome handling remain. Every remote mutation begins with audit status `requested`, never a fabricated `approved`; historical records may still contain `approved`. Migration and `forget-local` retain explicit local terminal confirmations. The code does not promote/invite/convert a group as a hidden prerequisite or automatically resend a mutation on an ambiguous failure.

## Operational limits

- Direct IPv4 TCP only; no proxy, VPN configuration, IPv6 fallback or arbitrary endpoint overrides.
- No background update/reconnect framework. A server may close an idle connection while code/2FA entry is pending; rerun deliberately with fresh state. Each actual I/O/RPC has a deadline.
- Login supports existing human accounts with ordinary code/2FA flows and bounded login DC migrations. It does not create accounts or configure email/passkeys; post-login DC migrations are surfaced as errors rather than silently exporting authorization to a new DC.
- Recoverable login-input mistakes retry only the relevant field in the current process. Only explicit server `PHONE_CODE_INVALID`/`PHONE_CODE_EMPTY` and `PASSWORD_HASH_INVALID` rejections allow another user-entered attempt; code delivery is not resent and SRP parameters are refreshed. Expired codes, flood waits, integrity failures and ambiguous submissions are not retried. Unfinished credentials are retained only in memory, not saved as a resumable plaintext draft.
- Dialog discovery is capped at 10,000; member-ID discovery at 10,000; list/search limits at 10,000; per-chat export count at 1,000,000. Hidden/missing access hashes fail, not guess.
- Disk budgets are per chat, not a global filesystem quota. Narrow bulk exports and use an OS/filesystem quota or separate volume; a deliberately large all-chat export can still exhaust available disk space.
- TL input/output max 8 MiB, depth/node/vector limits, gzip output bounds, PQ factoring budgets, and 60-second RPC deadlines reduce resource exhaustion but are not a formal DoS proof.
- A per-chat export replacement is atomic, but a multi-chat sync is not globally atomic. Resume is not an edit/delete mirror or older-history backfill.
- Folder updates recheck the filter before submission, but Telegram has no conditional compare-and-swap here; another client can still race the final refresh/update window. Do not edit the same filter concurrently.
- Crash/power loss can leave private temp files/locks. Never automatically delete a lock merely because a PID appears stale/reused. Verify no operation is active, then remove only the relevant files manually.
- A mutation with an audit `requested` or `approved` record but no final outcome may have succeeded. A success followed by an audit warning must not be retried blindly.

## Before using a real account

1. Independently review the TL codec, RSA/DH authentication, AES-IGE/packet state machine, SRP and secret lifecycle.
2. Opt in to a disposable Telegram **test-account** interoperability run: login, 2FA, status, pagination/search, folders, bounded export/resume and server-side logout. Use throwaway groups/users for each write.
3. Independently verify revocation in an official client and wrong-recipient/duplicate-name behavior.
4. Verify account/data retention and OS isolation. Do not import a primary session merely to “test” the implementation.
5. Consider adding reviewed temporary-key binding and a separate approval broker before sensitive deployments.

No step above was performed against the user's real Telegram account during development. There is no claim that the offline test count substitutes for these gates.

# Validation record

**Baseline snapshot (before the macOS/Windows port):** Node `v26.13.1`, Linux.

**Status:** **150/150 offline tests passed** on Node.js 26.0.0 and 26.13.1, with zero failures or skips. This is not a production/security certification.

Machine-readable results: [validation-results.json](validation-results.json).

Native V8 coverage: [coverage-summary.json](coverage-summary.json), [full source coverage table](coverage-report.txt).

## Checks run for this snapshot

```sh
npm run check
node scripts/verify.ts
node --test --experimental-test-coverage --test-coverage-include='src/**' \
  --test-reporter=spec 'tests/**/*.test.ts'
node bin/telegram.ts --help
```

`check` runs Oxlint, Oxfmt, and tsrs as well as the source and schema checks.
`verify` runs the source and schema checks and offline tests without requiring
development tools. The source checks enforce Node-compatible TypeScript syntax,
an 80-column limit, zero runtime npm dependencies, built-in/local imports,
native Temporal, the isolated credential-helper subprocess boundary, and
pinned schema integrity. Neither command contacts Telegram or invokes real
credential helpers.

An offline npm smoke test built and packed `telegram-0.1.0.tgz`, installed it
into a temporary global prefix with development dependencies omitted, and ran
the installed CLI with type stripping disabled. The installed help matched the
TypeScript checkout's help. The user's global npm installation was not modified.

The native source coverage snapshot is **93.79% lines / 82.15% branches /
94.83% functions**. Line coverage is sensitive to formatting. These are
source execution metrics, not coverage of every schema constructor, native
OpenSSL, cryptographic proof, API behavior, or server interaction. Real key
exchange and controlling-terminal CLI/network workflows are not covered
end-to-end.

## Minimum Node.js version

The supported minimum is **26.0.0**: it [enabled native Temporal by default](https://nodejs.org/en/blog/release/v26.0.0#temporal-api) and passed the CLI startup, source checks and all offline tests without flags. Node.js 24.18.0 and 25.9.0 had no default `Temporal` global and exited with the expected version message. Experimental flags and polyfills aren't supported. The npm engine range is `>=26.0.0`; later versions aren't blocked by a major-version cap and must still have native Temporal available.

## Platform validation

The macOS/Windows port adds mocked tests for native keyring selection,
exact-entry deletion and stdin-only writes, plus gopass tests for both
platforms. The offline CI matrix builds and tests on all three platforms.
On Linux, 157 tests passed (one native desktop test skipped). A separate
save/read/delete round trip passed with gopass 1.17.4 and a disposable
GPG-encrypted store. The Windows helper cross-compiled for x64 and ARM64.
Actual macOS and Windows credential stores and Windows console input have not
been exercised in this Linux environment.

To exercise the OS credential store under a signed-in desktop account, run
`npm run build:native`, then run the opt-in test below. It creates a
randomly named entry containing synthetic data and deletes it on cleanup.
It does not use your Telegram account or change an existing entry.

```sh
# macOS, in a session with the login keychain available
TELEGRAM_TEST_KEYRING=1 node --test tests/native-keyring.test.ts
```

```powershell
# Windows, from an interactive desktop session
$env:TELEGRAM_TEST_KEYRING = '1'
node --test tests/native-keyring.test.ts
Remove-Item Env:TELEGRAM_TEST_KEYRING
```

## What the offline tests exercise

| Area | Evidence |
| --- | --- |
| Native crypto composition | AES-256-IGE matches an independent OpenSSL `AES_ige_encrypt` fixture; modern RSA padding is decrypted/authenticated using independently generated native RSA keys; the sole RSA pin matches the production fingerprint and recomputes correctly. |
| DH / SRP | Native-DH agreement, pinned-prime/generator/public-value rejection, subgroup residue checks rejecting DH generator 5 for this prime, and SRP generator-3 and generator-5 proofs checked against independently computed fake server sessions. DH and SRP validators are separate. Secret whitespace is retained. |
| Key exchange negative path | A forged nonce is rejected before trusting/factoring the response. PQ factoring has size/prime/iteration bounds. A **complete successful handshake with a real Telegram key/server has not been exercised**. |
| Encrypted packets | Direction-specific key derivation, authenticated ciphertext, tampering/truncation, wrong auth/session IDs, server-ID parity, salt/time rejection, correlated unknown-salt recovery, containers, replay/duplicate IDs, bounded gzip/typed results, ACK behavior and explicit-rejection retries. Positive/negative stale-offset recovery accepts only bounded authenticated standalone clock corrections correlated to the active request and sequence; wrong salts/sessions/codes/directions/IDs/sequences and ordinary stale traffic fail. |
| Mutation uncertainty | Transport failure after submission is not blindly replayed. A known RPC success is not changed to unknown merely because its later ACK failed. Flood waits are surfaced without automatic retry. |
| TL codec | Native signed `bigint` fixtures, flags/two flag words, vectors, Unicode/optional false booleans, malformed markers/lengths/padding, unknown methods/fields/flag bits, depth/node/cumulative-decompression limits and 500 small malformed-input probes. |
| Transport | Pinned endpoint selection, fragmented/coalesced framing, oversized/negative/buffer-flood rejection and absolute deadlines that byte trickles cannot indefinitely extend. Tests inject a fake socket; no public socket is opened. |
| Identity and reads | Numeric-title spoofing, duplicate/partial-title rejection, exact `@numeric` usernames, account identity in audit metadata, unread/status/contact projections, service-only history pagination, dates/media metadata, global-search cursors and participant/admin pagination. Outgoing private messages without `fromId` use the authenticated account (or unknown), not the recipient; explicit authors and channel posts remain distinct. Inclusive date bounds are tested against exclusive-offset fake servers at zero, ordinary timestamps and the signed-32-bit ceiling. |
| Writes | Remote changes submit directly with stable identities, input validation and metadata-only `requested`/outcome audits; failed/ambiguous submissions are not blindly retried. Explicit admin rights; mute/unmute/kick/promotion/reply/folder/logout paths; explicit initial folder membership/categories and rejection of empty filters; pin preservation on addition; concurrent folder edit/creation rejection; current ownership-transfer method/SRP including basic groups; owner/member preconditions and 2FA still required. |
| Document uploads | Mocked send/reply without a terminal, exact small and large file parts and small-file checksum, caption and reply ID, pinned basename, size/path/symlink/FIFO checks, changed-file and part rejection handling, and no final-send replay after an ambiguous response. An encrypted mock transport verifies binary part framing, typed RPC results, and correlated media publication. No real Telegram upload was tested. |
| Attachment downloads | Exact chat/message selection, largest photo size, arbitrary document attachments, safe suffixes, bounded binary parts, file-reference refresh, and rejection of protected media, incomplete data, and existing output paths. Tests check private file modes, cleanup on failure, encrypted single-data-center RPC framing, and mock authorization exchange and cleanup across data centers. No live download or secondary authorization was tested. |
| Message deletion | One exact ID verified in the selected chat, explicit self/everyone scope, channel-specific RPC, rejection of missing or wrong-chat messages, metadata-only audits, and no automatic replay after an uncertain outcome. The CLI path was exercised without a terminal. No live message was deleted. |
| Login / logout | Mocked login DC migration, code/2FA secret callbacks, credential-manager persistence, revocation of a newly created authorization when persistence fails, server-revoking logout, and refusal to delete credentials replaced during an operation. Recoverable local validation/code/2FA failures retry only the relevant stage without re-prompting completed fields or re-sending code delivery; rejected SRP proofs fetch fresh parameters. Expired codes, flood waits, integrity failures and ambiguous submissions stop without retries; attempted secret buffers are cleared. |
| Credential managers | Fake keyring/gopass round trips; only nonsecret references on disk; pinned backends/profile-directory binding; malformed-reference rejection before helper calls; fixed helper paths, no shell, stdin-only secret payloads, discarded stderr, sanitized process/pipe failures, timeouts/output limits; gopass automatic clipboard copying disabled; manager read/write/delete failures; verified deletion without mistaking decryption failure for absence; concurrent-reference rollback preserving unrelated user data; old custom-vault files untouched. |
| Files / migration | Session encoding/validation; private modes; symlink/hard-link/unsafe-mode rejection; consistent normalized paths for reads, writes, directory sync, deletion, temporary-file commits and locks even with symlink-plus-`..` syntax; successful mock login does not spuriously revoke committed credentials; no silent overwrite/fallback; non-evaluating flat JSON5 migration; no imported write flag; no credential fields in preferences. |
| Export / resume | Private ID-based filenames, colliding/path-like titles, stale metadata cursor rejection by deriving from actual data, duplicate avoidance, quota/identity/truncated-record failures, no partial replacement, no silent overwrite of unrelated metadata and symlink/mode rejection. Version-2 account-bound headers/metadata reject cross-account and legacy/unbound resume before history fetch/replacement; 10,000 maximum-length peer IDs round-trip above 1 MiB within a consistent 4 MiB budget and entry-count limit. |
| CLI / output | Send/reply with stdin, `-m` or `--message` preserve exact Unicode, whitespace, newlines and shell-like literal text without a controlling terminal or temporary message files. Input sources are mutually exclusive; missing/duplicate options fail; invalid inline content is rejected before credentials/networking. Mute/unmute, kick/promotion, folder changes and logout also work without a controlling terminal using fake credentials/clients; all persist `requested`, not false approval, audits. Logout revokes and cleans up only the matching fake credential. Migration and `forget-local` still refuse to change credentials without terminal confirmation. Strict native option parsing/arity, no `--yes`, explicit global search/rights/backend selection, early input/missing-session errors, escaped controls/bidi and offline help/version; the removed app-passphrase option is rejected. Negative numeric queries/titles/ranks/paths/message text are preserved while peer arguments/options alone are canonicalized. |

All credentials, sessions, phone numbers, accounts, group members, transports, credential managers and helper subprocesses in the tests are **fake fixtures**. Temporary files are confined to fresh test directories and removed after tests. Optional POSIX pseudo-terminal integration tests confirm that local confirmation prompts/review stay on the controlling terminal with stdout/stderr redirected, and hidden input preserves whitespace without echo. CLI `auth` with an injected fake manager in a fresh temporary state directory verifies that the first question stays visible while idle, advances to the hidden API-hash question after a fake API ID, and cancels without credentials/network access. The visibility check inspects the final redraw, not merely text emitted before readline erased it. The PTY checks use system Python only as a driver (no packages/install); they skip if Python is unavailable, while Node-only tests still run. All ran and passed in this snapshot. No npm dependency was introduced; normal credential storage intentionally requires the selected system helper.

## Dependency/scope reduction

Runtime source imports only Node built-ins and local modules. The lockfile pins
the development tools and their platform-specific binaries; none are required
to run the CLI.

The generator verifies the SHA-256 of each official Telegram Desktop layer 232
input, parses both schema files as text, and keeps the allowed requests and
the constructors they depend on. Binary transport fields declared as `string`
are represented as bytes. The output contains **1,030 constructors / 43 RPC
definitions / 126,757 bytes** including the final newline. Both `--source`
and `--fetch` reproduced the checked-in output byte for byte; a modified
input was rejected. See [schema provenance](../src/protocol/provenance.json)
for hashes and the exact allowlist.

## Important gates still open

1. **Live interoperability:** no real Telegram connection, login, messages, member changes, ownership transfers, exports, session revocations, or credential migration were performed against the user's account. Module/RPC fixtures cannot prove that every request/response/state transition works against Telegram.
2. **Independent audit:** earlier independent read-only code-review rounds identified twelve supported findings. Their final clean snapshot predates the credential-storage rewrite and direct-operation policy changes and does not certify either. Remote-operation confirmation was intentionally removed at the user's request; the earlier approval policy no longer applies. Neither those reviews nor the current self-review constitute an independent cryptographic audit.
3. **Forward secrecy:** temporary authorization-key binding/rotation is not implemented; the permanent authorization key is used directly.
4. **Agent isolation:** remote operations have no extra approval gate; remaining TTY secret/local-confirmation prompts are not an external authorization boundary. An agent controlling the same OS identity/process/PTY can act with its credentials. A separate trusted broker/identity and OS policy are needed for stronger enforcement.
5. **Operational limits:** no background reconnect/update system, general session migration, CDN downloads, resumable uploads, or edit/delete archive reconciliation. Attachment downloads are capped at 20 MiB; document uploads are capped at 100 MiB. Member/dialog discovery and per-chat exports are bounded. Per-chat disk budgets are not a global disk quota; use narrow export scopes and an OS/filesystem quota or separate volume for large bulk exports.
6. **Concurrency:** file locks coordinate cooperating CLI processes, not hostile same-user processes/manual editors. Folder API refresh/update has no server-side compare-and-swap. Do not concurrently edit the same storage/archive/filter.
7. **Real credential-manager integration:** the disposable Linux gopass fixture did not exercise a user's GPG/pinentry, recipients or Git hooks. Linux Secret Service, macOS Keychain and Windows Credential Manager have not been exercised in this checkout. Manager writes and reference creation are not one transaction; crashes/cleanup failures can leave orphan entries or stale references.

The safe next validation phase is an **explicitly opted-in disposable account and throwaway groups**, followed by independent review—not importing a primary session to see what happens. See [../SECURITY.md](../SECURITY.md).

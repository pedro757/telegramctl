# telegram

Use your existing Telegram account from the terminal. Read your inbox without marking messages as read, search chats, send messages and files, or save a copy of your history.

Targets **Linux, macOS, and Windows** with **Node.js 26.0.0 or newer** and no
runtime npm dependencies. Node can show help from the TypeScript checkout
without a build:

```sh
node bin/telegram.ts --help
```

## Get started

**1. Install from this checkout**

- **Linux:** No compiler is needed.
- **macOS:** Install Xcode Command Line Tools (`xcode-select --install`).
- **Windows:** Install Visual Studio Build Tools with **Desktop development
  with C++** and a Windows SDK, then use a Developer PowerShell or Native Tools
  Command Prompt for your Node architecture.

```sh
npm ci --ignore-scripts
npm run build
npm install -g --omit=dev --ignore-scripts .
telegram --help
```

Run this from the project directory on the target OS. The build emits JavaScript
and, on macOS and Windows, a small native helper to `dist/` for npm installation.
To run the TypeScript source rather than install it, run `npm run build:native`
on macOS or Windows to build just that helper. This is a private package:
`npm install -g telegram` would install a different package from the registry.

**2. Sign in**

Get your API ID and API hash from [my.telegram.org/apps](https://my.telegram.org/apps), then run:

```sh
telegram auth login
telegram check
```

`auth login` asks for your API credentials, phone number, login code, and Telegram 2FA password if you use one. Enter them directly in your terminal.

By default, the CLI saves your login in the native credential store:

| OS | Default store | Default state directory |
| --- | --- | --- |
| Linux | Secret Service via `/usr/bin/secret-tool` (libsecret) | `~/.local/state/telegram` |
| macOS | Keychain | `~/Library/Application Support/TelegramCLI` |
| Windows | Credential Manager (Windows Credentials) | `%LOCALAPPDATA%\TelegramCLI` |

Linux needs a working Secret Service provider. On macOS, approve a Keychain
prompt only if you launched this trusted build; rebuilding the helper can
trigger a new prompt. On Windows, use an attached Windows Terminal or console
for sign-in. Keep state, downloads and exports on a local NTFS drive in a
private location, not in a network share or a junction/reparse-point path.

**gopass 1.17 or later** is available on all three platforms. Set up an
encrypted gopass store, then choose it with `telegram auth login --store gopass`.
Linux uses `/usr/bin/gopass`; macOS checks the
Homebrew and MacPorts locations. On Windows, set `TELEGRAM_GOPASS_PATH` to
the full path of the actual trusted `gopass.exe`, for example in PowerShell:

```powershell
$env:TELEGRAM_GOPASS_PATH = 'C:\Tools\gopass\gopass.exe'
telegram auth login --store gopass
```

If PowerShell blocks npm's `.ps1` launcher scripts, use `npm.cmd` and
`telegram.cmd`.

Use the same variable on Linux or macOS to override the executable path.
Keep it set for later commands using that profile. This variable names an
executable, not a secret. The CLI never falls back to a plaintext credential
file or changes the saved backend automatically.

> This client has been tested offline, but not against a live Telegram account or by an independent security auditor. Start with a disposable account.

**3. Find your chats**

```sh
telegram inbox
telegram chats --json
```

Use IDs from `chats` in the examples below: `user:123` for a person, `chat:123` for a basic group, and `channel:123` for a supergroup or channel. You can also use `@username` or `self` for Saved Messages. Exact chat titles work when they're unique.

## Everyday commands

### Read and search

```sh
telegram read channel:123 --limit 20 --since 1d
telegram search "deadline" --chat channel:123
telegram search "deadline" --all
```

Use `--json` for scripts or `--markdown` for a fenced JSON block. `--quiet` hides progress messages, not warnings. `telegram <command> --help` shows usage for that command.

### Download a message attachment

```sh
telegram read channel:123 --limit 20 --json
telegram download channel:123 456
telegram download channel:123 457 -o "$HOME/telegram-media"
```

Use the message ID from `read` or `search`. `download` saves one directly
attached file of any format, up to **20 MiB**, and prints its local path.
For photos, it saves the largest available size. Paths use the chat and
message IDs rather than the sender's filename. If no usable extension is
available, or a recognized image or audio type doesn't match its header, the
file gets `.bin`. By default it saves directly to the system Downloads folder
(the configured XDG Downloads folder on Linux, `~/Downloads` on macOS, and
the Downloads Known Folder on Windows). Use `-o`/`--output` to choose another
directory. The CLI creates a private directory if it doesn't exist, writes
private files, and never overwrites an existing file. It doesn't automatically
open anything or mark messages as read or played. If the system folder is a
symlink or is writable by other users, choose a safe directory with `-o`.
Protected or disappearing media, link previews, and Telegram CDN downloads
aren't supported.

### Send a message or file

```sh
telegram send @username -m "Are we still on for Friday?"
telegram reply channel:123 456 -m "Sounds good"
telegram send @username -f "$HOME/Documents/report.pdf"
telegram reply channel:123 456 -f "$HOME/Documents/report.pdf" -m "Here's the report"
```

For replies, `456` is the original message ID. `-f` / `--file` sends one nonempty local file up to **100 MiB** as a document, even if it's a photo or video. No temporary copy is made.

Text passed with `-m` / `--message` can show up in shell history or process listings. For sensitive text, use `--stdin` or run `telegram send @username` for a hidden prompt. With a file and no text option, the file goes out without a caption.

**Account changes don't ask for confirmation.** Check the account and recipient before sending. If a send times out after submission, check the chat before trying again.

### Delete a message

```sh
telegram delete user:123 456 --for-me
telegram delete channel:123 456 --for-everyone
```

Use the chat and message IDs from `read` or `search`. The CLI verifies that
the message belongs to that chat. `--for-me` only removes your copy and is
not available in channels or supergroups. `--for-everyone` requests removal
for all participants and is subject to Telegram's permissions. Choose one
scope explicitly: the command submits immediately and doesn't undo deletions
or delete existing local downloads and exports. If the result is uncertain,
check the chat before retrying.

### Organize chats and manage groups

```sh
telegram mute channel:123 --duration 1h
telegram unmute channel:123
telegram folders
telegram folder-create "Work" --include channel:123
telegram folder-add folder:2 channel:456
telegram members channel:123
telegram admins channel:123
```

Use `folder-remove` to take a chat out of a folder. For group administration, `promote` requires explicit `--rights`, and `transfer-owner` requires Telegram 2FA. In a supergroup or channel, `kick` is a **permanent viewing ban**, not just a removal.

### Export chat history

```sh
telegram sync --chat channel:123 --all --output "$HOME/telegram-archive"
telegram sync --chat channel:123 --all --resume --output "$HOME/telegram-archive"
```

Export files are **plain-text JSONL**. Keep them somewhere private and out of Git. Without `--all`, `--days`, or `--since`, the default is the last seven days. Without `--chat`, the command covers all discovered chats. `--resume` adds newer messages; it doesn't fill old gaps or reflect edits and deletions. Media appear as metadata, not downloaded files.

## Sessions and settings

- **Check the active account:** `telegram whoami`. For separate logins, use `--state-dir <private-directory>` consistently, including during `auth`.
- **Find local state:** The state directory listed above holds preferences, a reference to your saved login, and audit metadata. The credentials themselves stay in your keyring or gopass. Sign in separately on a new OS; copying the reference or syncing gopass doesn't move a profile.
- **Sign out:** `telegram auth logout` revokes this CLI session and removes its saved credential. It doesn't sign out other devices. The old `telegram logout` remains an alias. `telegram forget-local` deletes the saved credential only, asks for confirmation, and does **not** revoke the session.
- **Switch from an older setup:** `telegram migrate --from <legacy-config>` imports a supported owner-only JSON/JSON5 config after confirmation and leaves the source untouched. If you have an old `session.enc.json` vault, sign in again instead. Neither step revokes old sessions; use Telegram’s **Settings → Devices** to end them.

## OpenCode and development

To add the [Telegram skill](SKILL.md) to OpenCode, run this from the checkout:

```sh
mkdir -p "$HOME/.config/opencode/skills/telegram"
ln -s "$PWD/SKILL.md" "$HOME/.config/opencode/skills/telegram/SKILL.md"
```

If the skill is already linked, skip this step. The skill does not make your Telegram session read-only; only grant access to an agent you trust.

Install the development tools with `npm ci --ignore-scripts`, then run:

| Command | Purpose |
| --- | --- |
| `npm run format` | Format TypeScript and configuration with Oxfmt. |
| `npm run lint` | Lint source and tests with Oxlint and its tsrs backend. |
| `npm run typecheck` | Strictly check the CLI, source, and scripts with tsrs. |
| `npm run check` | Run all three checks plus source and schema validation. |
| `npm test` | Run the offline test suite. |
| `npm run build` | Emit npm-installable JavaScript and OS helper into `dist/`. |
| `npm run build:native` | Build only the platform helper (no-op on Linux). |

Oxfmt targets 80 columns, and the source checks enforce the limit in TypeScript.
Generated JSON and the npm lockfile are not reformatted. `npm test` and
`npm run verify` also work without the JavaScript development tools; build the
native helper first on Windows. No test uses a real Telegram account. See
[the validation record](docs/VALIDATION.md#platform-validation) for the opt-in
Keychain/Credential Manager test.

Regenerate the pinned schema with `npm run schema -- --fetch`, or use
`npm run schema -- --source <directory>` with local copies of both files listed
in the [schema provenance](src/protocol/provenance.json). Neither is needed at
runtime.

[Security and limits](SECURITY.md) · [Test results and Node.js compatibility](docs/VALIDATION.md) · [Design notes](docs/EVALUATION.md) · [Third-party notices](THIRD-PARTY-NOTICES.md)

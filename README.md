# telegramctl

Use Telegram from your terminal. Read your inbox without marking messages as
read, search your chats, send files, or save a local copy of your history.

## Get started

You’ll need **Node.js 26 or newer**. The CLI runs on Linux, macOS 13+ (Intel
and Apple silicon), and Windows (x64 and ARM64). You don’t need a compiler.

```sh
npm install -g telegramctl
```

> If npm says the package isn’t available yet, download the
> `telegramctl-npm` artifact from a successful
> [GitHub Actions run](https://github.com/pedro757/telegramctl/actions),
> unzip it, and run `npm install -g ./telegramctl-0.1.0.tgz`.

Get an **API ID and API hash** from [my.telegram.org/apps](https://my.telegram.org/apps).
Then sign in and take a look at your inbox:

```sh
telegramctl auth login
telegramctl auth check
telegramctl inbox
```

Enter your API credentials, phone number, login code, and any Telegram 2FA
password directly in your terminal. `auth check` verifies the saved login
without reading your chats. On Linux, the default login store needs
`secret-tool` (from libsecret) and a running Secret Service keyring. macOS
and Windows use their built-in credential stores.

> The CLI has been tested offline, not with a live Telegram account or an
> independent security audit. Start with a disposable account.

## Read, reply, and save files

Start with `telegramctl chats` to find a chat ID. The examples below use
`channel:123` for a channel or supergroup and `456` for a message ID. Use
`user:123` for a person, `chat:123` for a basic group, or `self` for Saved
Messages. You can also use an `@username` or an exact, unique chat title.

```sh
telegramctl read channel:123 --limit 20
telegramctl search "deadline" --chat channel:123
telegramctl reply channel:123 456 -m "Sounds good"
telegramctl send self -f ./report.pdf
telegramctl download channel:123 456
```

- **Search:** Use `--all` instead of `--chat` to search across chats. Add
  `--since 1d` to `read` to see only messages from the last day.
- **Send:** `-f` attaches one file up to **100 MiB**; add `-m` for a caption.
  For sensitive text, use `--stdin` or run `telegramctl send <peer>` for a
  hidden prompt. Text passed with `-m` can appear in your shell history.
- **Download:** Saves one attachment up to **20 MiB** to your system Downloads
  folder and prints its path. Use `-o <directory>` to save it elsewhere.
  Downloads never overwrite or open files. Protected or disappearing media
  are not supported.
- **Delete:** Use `telegramctl delete <peer> <message-id> --for-me` to remove
  your copy, or `--for-everyone` where Telegram allows it. Channels and
  supergroups require `--for-everyone`.

**Commands that change your account act immediately.** Check the account and
recipient first. If a send or deletion times out, check the chat before retrying.

## More commands

| What you want to do | Command |
| --- | --- |
| See which account you’re using | `telegramctl auth whoami` |
| Sign this CLI out | `telegramctl auth logout` |
| List your folders | `telegramctl folder list` |
| Show a folder | `telegramctl folder show folder:2` |
| Add a chat to a folder | `telegramctl folder add folder:2 channel:123` |
| List groups you administer | `telegramctl group list --admin` |
| See a group’s members or admins | `telegramctl group members channel:123` or `telegramctl group admins channel:123` |
| Mute a chat for an hour | `telegramctl mute channel:123 --duration 1h` |

Run `telegramctl --help` to see all commands, or try `telegramctl folder --help`
and `telegramctl group --help` for their subcommands. Add `--json` for scripts.
To remove a mute, run `telegramctl unmute <peer>`.

`group promote` requires explicit `--rights`, and `group transfer-owner`
requires Telegram 2FA. In a supergroup or channel, `group kick` is a permanent
viewing ban, not just a removal.

### Export a chat

```sh
telegramctl export --chat channel:123 --all -o ./telegram-archive
```

Without `--all`, `--days`, or `--since`, the export covers the last seven days.
Without `--chat`, it covers all discovered chats. To add newer messages later,
run the same command with `--resume`. It won’t fill older gaps or mirror edits
and deletions. Exports are **plain-text JSONL**, so keep them private and out
of Git. Attachments appear as metadata, not downloaded files.

<details>
<summary>Login storage, gopass, and troubleshooting</summary>

| OS | Default credential store | Local state directory |
| --- | --- | --- |
| Linux | Secret Service via `/usr/bin/secret-tool` | `~/.local/state/telegram` |
| macOS | Keychain | `~/Library/Application Support/TelegramCLI` |
| Windows | Credential Manager | `%LOCALAPPDATA%\TelegramCLI` |

The state directory holds preferences, a login reference, and audit metadata,
not the credentials. To keep separate logins, pass the same
`--state-dir <private-directory>` at sign-in and on later commands for that
account. Copying the directory to another OS doesn’t move the login.

If you already use an encrypted **gopass 1.17+** store, sign in with
`telegramctl auth login --store gopass`. Linux uses `/usr/bin/gopass`; macOS
checks common Homebrew and MacPorts paths. On Windows, set the path to the
trusted executable before signing in:

```powershell
$env:TELEGRAMCTL_GOPASS_PATH = 'C:\Tools\gopass\gopass.exe'
telegramctl auth login --store gopass
```

You can use `TELEGRAMCTL_GOPASS_PATH` to override the path on Linux and macOS
too. Keep it set when using that login. The CLI never silently switches
stores or falls back to a plaintext credential file.

- **Windows:** Sign in from Windows Terminal or another attached console. Keep
  state and output on a private local NTFS path, not a network share or
  junction. If PowerShell blocks `.ps1` launchers, use `npm.cmd` and
  `telegramctl.cmd`.
- **macOS:** Only approve a Keychain prompt if you recognize the build you
  launched. Rebuilding the native helper can trigger another prompt.
- **Downloads:** If your Downloads folder is a symlink or is writable by
  others, choose a safe directory with `-o`.
- **Recovery:** `auth logout` revokes this CLI’s Telegram session, not other
  devices. `auth forget-local` deletes the saved login after confirmation but
  does **not** revoke it. `auth migrate --from <file>` imports a supported
  owner-only legacy config without touching the original. If you have an old
  `session.enc.json` vault, sign in again. Use Telegram’s **Settings → Devices**
  to end old sessions.

</details>

## Use with OpenCode

The npm package includes an OpenCode [skill](SKILL.md). On Linux or macOS,
link it once after installing the package:

```sh
mkdir -p "$HOME/.config/opencode/skills/telegramctl"
ln -s "$(npm root -g)/telegramctl/SKILL.md" "$HOME/.config/opencode/skills/telegramctl/SKILL.md"
```

Only grant access to an agent you trust. The skill does not make your
Telegram session read-only.

<details>
<summary>Build from source or publish a release</summary>

Source builds need Xcode Command Line Tools on macOS or the C++ workload and
Windows SDK in Visual Studio Build Tools on Windows. On Windows, build from
the Visual Studio Developer shell for the target architecture. Linux does not
need a compiler.

```sh
npm ci --ignore-scripts
npm run check
npm test
npm run build
```

`npm run build:native` builds just the OS helper. See the
[validation record](docs/VALIDATION.md) for the optional desktop keyring test
and the [design notes](docs/EVALUATION.md) for implementation details.

For releases, download the `telegramctl-npm` artifact from a passing
[Test and package run](https://github.com/pedro757/telegramctl/actions).
Sign in with `npm login`, then run
`npm publish ./telegramctl-<version>.tgz --access public` and approve the npm
2FA prompt. Publish the CI tarball: a local build only contains your platform’s
helper.

</details>

[Security and limits](SECURITY.md) ·
[Report an issue](https://github.com/pedro757/telegramctl/issues) ·
[Third-party notices](THIRD-PARTY-NOTICES.md)

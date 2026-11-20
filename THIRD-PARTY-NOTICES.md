# Upstream attribution

## Telegram protocol

The generated layer 232 schema describes the Telegram wire protocol using
[schema declarations][scheme] from the official Telegram Desktop repository.
The pinned input hashes are recorded in [schema provenance][provenance]. The
production RSA modulus is taken from the published public key in [the same
revision][keys]. These are protocol declarations and public-key data; no
Telegram Desktop implementation code is bundled.

Telegram Desktop is copyright © 2014–2026 The Telegram Desktop Authors; see
its [license notice][legal].

The local cryptographic glue follows Telegram's published [transport][transport],
[authorization key exchange][auth], and [password SRP][srp] specifications.
It uses Node/OpenSSL for cryptographic primitives.

[scheme]: https://github.com/telegramdesktop/tdesktop/tree/850fb90eb6db96c124b6da1349060f9ed00f4fe4/Telegram/SourceFiles/mtproto/scheme
[provenance]: src/protocol/provenance.json
[keys]: https://github.com/telegramdesktop/tdesktop/blob/850fb90eb6db96c124b6da1349060f9ed00f4fe4/Telegram/SourceFiles/mtproto/mtproto_dc_options.cpp
[legal]: https://github.com/telegramdesktop/tdesktop/blob/850fb90eb6db96c124b6da1349060f9ed00f4fe4/LEGAL
[transport]: https://core.telegram.org/mtproto/description
[auth]: https://core.telegram.org/mtproto/auth_key
[srp]: https://core.telegram.org/api/srp

## Skill inspiration

The requested CLI/skill use cases were evaluated against `skillhq/telegram`
at `919e32b1646eb24ed5e39234846563890ca0df4e` by Derek Rein (package license:
MIT). This repository's CLI, security policy, and skill instructions are newly
written; no original installer or executable CLI code is copied.

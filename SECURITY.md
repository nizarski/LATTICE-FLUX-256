# Security

I only support version 2.1.x right now.

LF-256 is a personal research project. It's not TLS. It's not ML-KEM. Read docs/TECH.md for what it can and can't do.

## Found a bug?

Don't open a public GitHub issue if it's exploitable. Message me (nizarski) privately.

Send: version, how to reproduce, what you think it breaks.

## If you actually use this

- Use a strong random passphrase.
- Keep keys in `.lf256.keys.enc`, not plain `.keys.json`.
- Sync clocks (NTP) if you're using the time-bound handshake.
- Don't expose the chat server to the internet without something like TLS in front.
- Default bind is 127.0.0.1 for a reason.

## What I won't fix in this repo

- Making Python constant-time.
- Proving the custom KEM is as strong as ML-KEM.

Those need a different codebase or a formal analysis I haven't done.

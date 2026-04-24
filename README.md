# nono-git-sign

GPG-signed git commits from inside [nono](https://nono.sh) sandboxes.

Sandboxed processes can't access `~/.gnupg`, so their commits show up as unverified. nono-git-sign fixes this: a daemon outside the sandbox holds the key and signs on behalf of the sandboxed process, after validating that the payload is a real git object.

## How it works

```
sandbox                              host
┌──────────────────┐     TCP      ┌──────────────────┐
│ git commit -S    │────────────▶│ git-sign-proxy   │
│   └─ gpg.program │  localhost   │   ├─ validate    │
│      = git-sign- │    :21639    │   │ (hash-object)│
│        proxy-    │◀────────────│   └─ gpg sign    │
│        client    │  signature   │                  │
└──────────────────┘              └──────────────────┘
```

- **git-sign-proxy** — systemd user service that validates payloads with `git hash-object` and signs with `gpg`. Itself sandboxed with the nono SDK.
- **git-sign-proxy-client** — drop-in `gpg.program` replacement. Reads stdin, sends to daemon, writes signature to stdout.

## Usage

### Install

```bash
./install.sh
```

Builds release binaries, copies them to `~/.cargo/bin/`, and enables the systemd user service.

Edit `systemd/git-sign-proxy.service` to set your GPG key ID before installing.

### Configure the sandbox

Allow the sandboxed process to reach the daemon:

```bash
nono run --open-port 21639 ...
```

Inside the sandbox, point git at the proxy client:

```bash
git config gpg.program git-sign-proxy-client
```

That's it. `git commit -S` now signs through the proxy.

### Daemon options

| Flag | Default | Description |
|------|---------|-------------|
| `--port` | 21639 | TCP listen port |
| `--key` | (required) | GPG key ID |
| `--max-payload` | 1048576 | Max payload bytes |

The client reads `GIT_SIGN_PROXY_PORT` to override the default port.

### Logs

```bash
journalctl --user -u git-sign-proxy -f
```

## Security

- The sandboxed process never touches `~/.gnupg` or the gpg-agent socket
- The daemon validates every payload is a genuine git commit or tag object before signing — arbitrary data is rejected
- The signing key is configured daemon-side; the client can't choose a different key
- The daemon process is itself Landlock-sandboxed via the nono SDK (filesystem + network restricted)

## Building from source

Requires Rust 1.70+.

```bash
cargo build --release
cargo test
```

## License

MIT

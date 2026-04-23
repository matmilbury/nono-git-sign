# git-sign-proxy

A localhost TCP proxy that lets [nono](https://nono.sh)-sandboxed processes create GPG-signed git commits without direct access to private key material.

## Problem

AI agents running in nono sandboxes can't access `~/.gnupg` (blocked by `deny_credentials`). But we want their git commits to be GPG-signed and show as "Verified" on GitHub.

## How It Works

Two components:

- **`git-sign-proxy`** — daemon running as a systemd user service on `localhost:21639`. Has access to GPG keys. Validates that incoming payloads are real git commit/tag objects before signing them.
- **`git-sign-proxy-client`** — tiny binary set as `gpg.program` inside the sandbox. Reads from stdin, sends to daemon over TCP, writes signature to stdout.

The sandbox connects to the daemon via nono's `--open-port 21639`.

## Security

- Agent never accesses `~/.gnupg` or the gpg-agent socket
- Daemon validates payloads are git commit/tag objects using `git hash-object`
- Daemon process is itself sandboxed with the nono Rust SDK
- Signing key is configured daemon-side only — agent can't choose a different key
- All requests are logged to journald

## Install

```bash
./install.sh
```

This builds both binaries, installs them to `~/.cargo/bin/`, and sets up the systemd user service.

## Usage

The daemon runs automatically via systemd. In your sandbox launcher, add:

```bash
nono run --open-port 21639 ...
```

And configure git in the sandboxed worktree:

```bash
git config gpg.program git-sign-proxy-client
```

### workon.nu Integration

Three changes are needed in `~/.config/claude-agents/scripts/workon.nu`:

1. **Service startup check** — before launching Claude, ensure the service is running:
   ```nu
   let proxy_status = (do { systemctl --user is-active git-sign-proxy.service } | complete)
   if $proxy_status.exit_code != 0 {
       print "Starting git-sign-proxy service..."
       do { systemctl --user start git-sign-proxy.service } | complete
   }
   ```

2. **Open port** — add `--open-port 21639` to the nono invocation

3. **Configure gpg.program** — after worktree creation:
   ```nu
   git -C $worktree_path config gpg.program git-sign-proxy-client
   ```

## Configuration

Daemon flags (set in systemd unit file):
- `--port <PORT>` — TCP port (default: 21639)
- `--key <KEYID>` — GPG key ID (required)
- `--max-payload <BYTES>` — max payload size (default: 1048576)

Client env vars:
- `GIT_SIGN_PROXY_PORT` — override daemon port (default: 21639)

## Logs

```bash
journalctl --user -u git-sign-proxy -f
```

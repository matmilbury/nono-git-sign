#!/bin/bash
# Install git-sign-proxy: build, install binary, set up systemd service.
set -euo pipefail

echo "Building release binaries..."
cargo build --release

echo "Installing binaries to ~/.cargo/bin/..."
cp target/release/git-sign-proxy ~/.cargo/bin/
cp target/release/git-sign-proxy-client ~/.cargo/bin/

echo "Installing systemd user service..."
mkdir -p ~/.config/systemd/user
cp systemd/git-sign-proxy.service ~/.config/systemd/user/

echo "Reloading systemd..."
systemctl --user daemon-reload

echo "Enabling and starting service..."
systemctl --user enable git-sign-proxy.service
systemctl --user start git-sign-proxy.service

echo "Done! Check status with: systemctl --user status git-sign-proxy"
echo "View logs with: journalctl --user -u git-sign-proxy -f"

// GPG signing: produces detached ASCII-armored signatures.
//
// Calls `gpg -bsau <key_id>` with the payload on stdin.
// The flags mean:
//   -b  detached signature (separate from the data)
//   -s  sign
//   -a  ASCII-armor the output (text, not binary)
//   -u  use this key ID

use std::io::Write;
use std::process::{Command, Stdio};

use log::{debug, error};

/// Sign the given payload with GPG using the specified key ID.
/// Returns the ASCII-armored detached signature on success.
pub fn gpg_sign(payload: &[u8], key_id: &str) -> Result<Vec<u8>, String> {
    let mut child = Command::new("gpg")
        .args([
            "--batch",
            "--yes",
            "--pinentry-mode", "loopback",
            "-bsau", key_id,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("failed to spawn gpg: {}", e))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(payload)
            .map_err(|e| format!("failed to write to gpg stdin: {}", e))?;
    }

    let output = child
        .wait_with_output()
        .map_err(|e| format!("failed to wait for gpg: {}", e))?;

    if output.status.success() {
        debug!("gpg signing succeeded ({} bytes)", output.stdout.len());
        Ok(output.stdout)
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        error!("gpg signing failed: {}", stderr);
        Err(format!("gpg signing failed (exit {})", output.status))
    }
}

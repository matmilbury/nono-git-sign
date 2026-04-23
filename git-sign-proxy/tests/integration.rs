// End-to-end integration test for git-sign-proxy.
//
// Starts the daemon, sends a valid commit object via TCP using the protocol
// library, and verifies a GPG signature is returned.
//
// Requirements:
// - GPG key must be available (the key ID from git config user.signingkey)
// - gpg-agent must be running with cached passphrase
//
// Run with: cargo test -p git-sign-proxy --test integration

use std::net::TcpStream;
use std::process::{Child, Command};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

use git_sign_proxy_protocol::{self as proto, Request, Status};

/// Each test gets a unique port to avoid conflicts.
static NEXT_PORT: AtomicU16 = AtomicU16::new(31639);

fn next_port() -> u16 {
    NEXT_PORT.fetch_add(1, Ordering::SeqCst)
}

/// Get the GPG signing key from git config.
fn get_signing_key() -> String {
    let output = Command::new("git")
        .args(["config", "--global", "user.signingkey"])
        .output()
        .expect("failed to run git config");
    String::from_utf8(output.stdout)
        .expect("invalid utf8")
        .trim()
        .to_string()
}

/// Start the daemon as a background process. Returns the Child handle.
fn start_daemon(key: &str, port: u16) -> Child {
    let child = Command::new(env!("CARGO_BIN_EXE_git-sign-proxy"))
        .args(["--port", &port.to_string(), "--key", key])
        .env("RUST_LOG", "debug")
        .spawn()
        .expect("failed to start daemon");

    std::thread::sleep(Duration::from_millis(500));
    child
}

/// Build a minimal valid git commit object.
fn make_commit(message: &str) -> Vec<u8> {
    format!(
        "tree 4b825dc642cb6eb9a060e54bf899d69f2b1e28c2\n\
         author Test User <test@example.com> 1700000000 +0000\n\
         committer Test User <test@example.com> 1700000000 +0000\n\
         \n\
         {}",
        message
    )
    .into_bytes()
}

/// Send a payload to the daemon and get the response.
fn send_request(payload: Vec<u8>, port: u16) -> proto::Response {
    let mut stream =
        TcpStream::connect(("127.0.0.1", port)).expect("failed to connect to daemon");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();

    proto::write_request(&mut stream, &Request { payload }).unwrap();
    stream.shutdown(std::net::Shutdown::Write).unwrap();
    proto::read_response(&mut stream).unwrap()
}

#[test]
fn signs_valid_commit() {
    let key = get_signing_key();
    if key.is_empty() {
        eprintln!("SKIP: no git signing key configured");
        return;
    }

    let port = next_port();
    let mut daemon = start_daemon(&key, port);

    let payload = make_commit("integration test commit");
    let response = send_request(payload, port);

    daemon.kill().ok();
    daemon.wait().ok();

    assert_eq!(response.status, Status::Success);
    let sig = String::from_utf8_lossy(&response.body);
    assert!(
        sig.contains("BEGIN PGP SIGNATURE"),
        "expected PGP signature, got: {}",
        sig
    );
}

#[test]
fn rejects_invalid_payload() {
    let key = get_signing_key();
    if key.is_empty() {
        eprintln!("SKIP: no git signing key configured");
        return;
    }

    let port = next_port();
    let mut daemon = start_daemon(&key, port);

    let response = send_request(b"this is not a git object".to_vec(), port);

    daemon.kill().ok();
    daemon.wait().ok();

    assert_eq!(response.status, Status::ValidationError);
}

#[test]
fn rejects_empty_payload() {
    let key = get_signing_key();
    if key.is_empty() {
        eprintln!("SKIP: no git signing key configured");
        return;
    }

    let port = next_port();
    let mut daemon = start_daemon(&key, port);

    let response = send_request(b"".to_vec(), port);

    daemon.kill().ok();
    daemon.wait().ok();

    assert_ne!(response.status, Status::Success);
}

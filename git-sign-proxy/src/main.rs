// git-sign-proxy: a localhost TCP daemon that validates and signs git objects.
//
// It listens on a TCP port and handles signing requests from sandboxed agents.
// Each request is: validate the payload is a git commit/tag, then GPG-sign it.
//
// Usage:
//   git-sign-proxy --port 21639 --key 1CD26C38E6D6D7E7

mod sign;
mod validate;

use std::io::Read;
use std::net::TcpListener;

use clap::Parser;
use log::{error, info, warn};

use git_sign_proxy_protocol::{self as proto, Response, Status, MAX_PAYLOAD_SIZE};

/// Command-line arguments for the daemon.
#[derive(Parser)]
#[command(name = "git-sign-proxy", about = "GPG signing proxy for sandboxed agents")]
struct Args {
    /// TCP port to listen on.
    #[arg(long, default_value_t = 21639)]
    port: u16,

    /// GPG key ID to sign with (e.g., 1CD26C38E6D6D7E7).
    #[arg(long)]
    key: String,

    /// Maximum payload size in bytes.
    #[arg(long, default_value_t = MAX_PAYLOAD_SIZE)]
    max_payload: u32,
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = Args::parse();

    // === Apply Landlock sandbox ===
    // Restrict this daemon process (and all children) to only what's needed.
    // This is defense-in-depth: even if a crafted payload exploits git or gpg,
    // the process can't access anything beyond these paths.
    apply_sandbox(&args);

    let bind_addr = format!("127.0.0.1:{}", args.port);
    let listener = TcpListener::bind(&bind_addr).unwrap_or_else(|e| {
        error!("failed to bind to {}: {}", bind_addr, e);
        std::process::exit(1);
    });

    info!("listening on {} (key: {})", bind_addr, args.key);

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(30)));

                let response = handle_request(&mut stream, &args.key, args.max_payload);
                if let Err(e) = proto::write_response(&mut stream, &response) {
                    warn!("failed to send response: {}", e);
                }
            }
            Err(e) => {
                warn!("failed to accept connection: {}", e);
            }
        }
    }
}

/// Process a single signing request: read it, validate, sign, return response.
fn handle_request(
    stream: &mut (impl Read + std::io::Write),
    key_id: &str,
    max_payload: u32,
) -> Response {
    let request = match proto::read_request(stream) {
        Ok(r) => r,
        Err(e) => {
            warn!("bad request: {}", e);
            return Response {
                status: Status::ValidationError,
                body: format!("bad request: {}", e).into_bytes(),
            };
        }
    };

    let first_line = String::from_utf8_lossy(&request.payload)
        .lines()
        .next()
        .unwrap_or("<empty>")
        .to_string();
    info!("request: {} ({} bytes)", first_line, request.payload.len());

    if request.payload.len() as u32 > max_payload {
        warn!("rejected: payload too large ({} bytes)", request.payload.len());
        return Response {
            status: Status::ValidationError,
            body: b"payload exceeds maximum size".to_vec(),
        };
    }

    match validate::validate_git_object(&request.payload) {
        Ok(obj_type) => {
            info!("validated as {:?}", obj_type);
        }
        Err(msg) => {
            warn!("rejected: {}", msg);
            return Response {
                status: Status::ValidationError,
                body: msg.into_bytes(),
            };
        }
    }

    match sign::gpg_sign(&request.payload, key_id) {
        Ok(signature) => {
            info!("signed ({} bytes signature)", signature.len());
            Response {
                status: Status::Success,
                body: signature,
            }
        }
        Err(msg) => {
            error!("signing failed: {}", msg);
            Response {
                status: Status::SigningError,
                body: msg.into_bytes(),
            }
        }
    }
}

/// Apply a nono sandbox to restrict the daemon's filesystem and network access.
/// On unsupported platforms, logs a warning and continues without sandbox.
fn apply_sandbox(args: &Args) {
    if !nono::Sandbox::is_supported() {
        warn!("nono sandbox not supported on this platform — running without sandbox");
        return;
    }

    let home = std::env::var("HOME").unwrap_or_else(|_| "/home".to_string());
    let gnupg_dir = format!("{}/.gnupg", home);

    // Determine gpg-agent socket dir from UID.
    let uid = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Uid:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|u| u.parse::<u32>().ok())
        })
        .unwrap_or(1000);
    let gpg_socket_dir = format!("/run/user/{}/gnupg", uid);

    let gitconfig = format!("{}/.gitconfig", home);

    let mut caps = nono::CapabilitySet::new()
        // Read-only: git and gpg binaries, shared libraries.
        .allow_path("/usr", nono::AccessMode::Read)
        .expect("allow /usr")
        .allow_path("/lib", nono::AccessMode::Read)
        .expect("allow /lib")
        // Read-only: git config (needed by git hash-object).
        .allow_file(&gitconfig, nono::AccessMode::Read)
        .expect("allow ~/.gitconfig")
        // Read-write: GPG keyring dir (gpg creates lock files here).
        .allow_path(&gnupg_dir, nono::AccessMode::ReadWrite)
        .expect("allow ~/.gnupg")
        // Read-write: /dev for /dev/null (used by git).
        .allow_path("/dev", nono::AccessMode::ReadWrite)
        .expect("allow /dev")
        // Read-write: GPG agent socket.
        .allow_path(&gpg_socket_dir, nono::AccessMode::ReadWrite)
        .expect("allow gpg socket dir")
        // Read-write: /tmp for GPG temporary files.
        .allow_path("/tmp", nono::AccessMode::ReadWrite)
        .expect("allow /tmp")
        // Network: only allow binding our port.
        .allow_tcp_bind(args.port);

    if std::path::Path::new("/lib64").exists() {
        caps = caps
            .allow_path("/lib64", nono::AccessMode::Read)
            .expect("allow /lib64");
    }

    if std::path::Path::new("/etc").exists() {
        caps = caps
            .allow_path("/etc", nono::AccessMode::Read)
            .expect("allow /etc");
    }

    match nono::Sandbox::apply(&caps) {
        Ok(_) => info!("nono sandbox applied"),
        Err(e) => {
            error!("failed to apply nono sandbox: {}", e);
            std::process::exit(1);
        }
    }
}

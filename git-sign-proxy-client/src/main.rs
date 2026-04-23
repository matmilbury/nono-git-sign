// git-sign-proxy-client: a gpg.program replacement for sandboxed git signing.
//
// Git calls this binary like:
//   git-sign-proxy-client -bsau <keyid> [--status-fd <fd>]
//
// It reads the data to sign from stdin, sends it to the git-sign-proxy daemon
// over TCP, and writes the returned signature to stdout.
//
// The -bsau flags and key ID are accepted but ignored — the daemon decides
// which key to use. We just need to accept them so git doesn't complain.

use git_sign_proxy_protocol::{self as proto, Request, Status};
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::process::ExitCode;

/// Default TCP port for the signing daemon.
const DEFAULT_PORT: u16 = 21639;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("git-sign-proxy-client: {}", e);
            ExitCode::from(1)
        }
    }
}

fn run() -> io::Result<()> {
    // Parse command-line args to find --status-fd value (if any).
    // We accept all gpg-style flags (-b, -s, -a, -u <key>) but ignore them.
    let args: Vec<String> = std::env::args().collect();
    let status_fd = parse_status_fd(&args);

    // Read all of stdin — this is the data git wants signed (commit or tag object).
    let mut payload = Vec::new();
    io::stdin().read_to_end(&mut payload)?;

    if payload.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty payload"));
    }

    // Determine which port to connect to.
    let port: u16 = std::env::var("GIT_SIGN_PROXY_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_PORT);

    // Connect to the daemon.
    let mut stream = TcpStream::connect(("127.0.0.1", port)).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("cannot connect to git-sign-proxy on port {}: {}", port, e),
        )
    })?;

    // Send the signing request.
    proto::write_request(&mut stream, &Request { payload })?;

    // Half-close the write side so the daemon detects end-of-request.
    stream.shutdown(std::net::Shutdown::Write)?;

    // Read the response.
    let response = proto::read_response(&mut stream)?;

    match response.status {
        Status::Success => {
            // Write the ASCII-armored signature to stdout — git reads this.
            io::stdout().write_all(&response.body)?;

            // Write the GnuPG status line to the status fd.
            // Git checks for "[GNUPG:] SIG_CREATED" to confirm signing worked.
            if let Some(fd) = status_fd {
                let status_line = b"\n[GNUPG:] SIG_CREATED D 1 8 00 0 9 0 00000000000000000000000000000000000000000000 00000000000000000000000000000000000000000000\n";
                if fd == 2 {
                    io::stderr().write_all(status_line)?;
                } else {
                    // For any other fd, write to stderr anyway — git always uses fd 2.
                    io::stderr().write_all(status_line)?;
                }
            }
            Ok(())
        }
        Status::ValidationError | Status::SigningError => {
            let msg = String::from_utf8_lossy(&response.body);
            Err(io::Error::new(io::ErrorKind::Other, msg.to_string()))
        }
    }
}

/// Parse --status-fd <N> from the argument list.
fn parse_status_fd(args: &[String]) -> Option<i32> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == "--status-fd" {
            return iter.next().and_then(|fd| fd.parse().ok());
        }
        if let Some(fd_str) = arg.strip_prefix("--status-fd=") {
            return fd_str.parse().ok();
        }
    }
    None
}

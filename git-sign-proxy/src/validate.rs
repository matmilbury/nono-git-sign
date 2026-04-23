// Content validation: ensures payloads are real git objects before signing.
//
// Uses `git hash-object --stdin -t commit` (or -t tag) to validate. This is
// safer than hand-parsing because we use git's own parser — if git accepts it,
// it's a valid git object.
//
// Safety notes (why this is safe with untrusted input):
// - `--stdin` without `--path` prevents gitattributes filter execution
// - Without `--literally`, git validates object format strictly
// - Without `-w`, git does not write to disk
// - Data is piped via Command::new(), not through a shell (no shell injection)

use std::io::Write;
use std::process::{Command, Stdio};

use log::debug;

/// The two kinds of git objects we allow signing.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum GitObjectType {
    Commit,
    Tag,
}

/// Check if the payload is a valid git commit or tag object.
/// Returns Ok(type) if valid, Err(message) if not.
pub fn validate_git_object(payload: &[u8]) -> Result<GitObjectType, String> {
    if try_hash_object(payload, "commit") {
        debug!("validated as git commit object");
        Ok(GitObjectType::Commit)
    } else if try_hash_object(payload, "tag") {
        debug!("validated as git tag object");
        Ok(GitObjectType::Tag)
    } else {
        Err("payload is not a valid git commit or tag object".to_string())
    }
}

/// Run `git hash-object --stdin -t <type>` with the given payload.
/// Returns true if git accepts it as a valid object of that type.
fn try_hash_object(payload: &[u8], object_type: &str) -> bool {
    let child = Command::new("git")
        .args(["hash-object", "--stdin", "-t", object_type])
        // Run from /tmp so git doesn't need access to the daemon's cwd
        // (which may be outside the sandbox's allowed paths).
        .current_dir("/tmp")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();

    let mut child = match child {
        Ok(c) => c,
        Err(e) => {
            debug!("failed to spawn git: {}", e);
            return false;
        }
    };

    if let Some(mut stdin) = child.stdin.take() {
        if stdin.write_all(payload).is_err() {
            return false;
        }
    }

    match child.wait() {
        Ok(status) => status.success(),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn make_tag(tag_name: &str) -> Vec<u8> {
        format!(
            "object 4b825dc642cb6eb9a060e54bf899d69f2b1e28c2\n\
             type commit\n\
             tag {}\n\
             tagger Test User <test@example.com> 1700000000 +0000\n\
             \n\
             tag message",
            tag_name
        )
        .into_bytes()
    }

    #[test]
    fn accepts_valid_commit() {
        let payload = make_commit("test commit");
        let result = validate_git_object(&payload);
        assert_eq!(result.unwrap(), GitObjectType::Commit);
    }

    #[test]
    fn accepts_valid_tag() {
        let payload = make_tag("v1.0.0");
        let result = validate_git_object(&payload);
        assert_eq!(result.unwrap(), GitObjectType::Tag);
    }

    #[test]
    fn rejects_arbitrary_text() {
        let payload = b"this is not a git object at all";
        let result = validate_git_object(payload);
        assert!(result.is_err());
    }

    #[test]
    fn rejects_partial_commit() {
        let payload = b"tree 4b825dc642cb6eb9a060e54bf899d69f2b1e28c2\nauthor A <a@b> 1 +0000\n\ntest";
        let result = validate_git_object(payload);
        assert!(result.is_err());
    }

    #[test]
    fn rejects_empty_payload() {
        let result = validate_git_object(b"");
        assert!(result.is_err());
    }

    #[test]
    fn rejects_shell_injection_attempt() {
        let payload = b"$(rm -rf /) tree 0000000000000000000000000000000000000000\nauthor A <a@b> 1 +0000\ncommitter A <a@b> 1 +0000\n\ntest";
        let result = validate_git_object(payload);
        assert!(result.is_err());
    }
}

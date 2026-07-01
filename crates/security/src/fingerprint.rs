//! Host-key fingerprints in the `SHA256:base64` form OpenSSH prints (§5.1).

use base64::Engine;
use sha2::{Digest, Sha256};

/// `SHA256:<base64-no-padding>` over the raw SSH public-key blob, exactly as
/// `ssh-keygen -l -f` reports it, so users can eyeball-match against their
/// own records during first-contact verification (§5.1).
pub fn sha256_fingerprint(public_key_blob: &[u8]) -> String {
    let digest = Sha256::digest(public_key_blob);
    let b64 = base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest);
    format!("SHA256:{b64}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vector() {
        // Empty input has a stable SHA-256; just assert the shape + prefix.
        let fp = sha256_fingerprint(b"");
        assert!(fp.starts_with("SHA256:"));
        assert!(!fp.ends_with('='));
    }
}

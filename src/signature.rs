use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Compute HMAC-SHA256 signature in hexadecimal
pub fn sign_hmac_sha256(secret: &[u8], data: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC can take key of any size");
    mac.update(data);
    hex::encode(mac.finalize().into_bytes())
}

/// Verify HMAC-SHA256 signature against header (supporting "sha256=<hex>" or raw "<hex>")
pub fn verify_hmac_sha256(secret: &[u8], data: &[u8], signature_header: &str) -> bool {
    let raw_hex = signature_header
        .strip_prefix("sha256=")
        .unwrap_or(signature_header)
        .trim();

    let expected_bytes = match hex::decode(raw_hex) {
        Ok(b) => b,
        Err(_) => return false,
    };

    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC can take key of any size");
    mac.update(data);
    mac.verify_slice(&expected_bytes).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_and_verify() {
        let secret = b"my_super_secret_key";
        let body = b"{\"event\":\"order.created\",\"id\":1234}";

        let sig = sign_hmac_sha256(secret, body);
        assert!(!sig.is_empty());

        // Verify with raw hex
        assert!(verify_hmac_sha256(secret, body, &sig));

        // Verify with sha256= prefix
        let prefixed = format!("sha256={}", sig);
        assert!(verify_hmac_sha256(secret, body, &prefixed));

        // Verify with wrong body
        assert!(!verify_hmac_sha256(secret, b"wrong body", &prefixed));

        // Verify with wrong secret
        assert!(!verify_hmac_sha256(b"wrong_secret", body, &prefixed));
    }
}

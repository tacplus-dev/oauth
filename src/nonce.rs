use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm,
};
use base64::Engine;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

use fleetwood_tacplus::types::services::fleetwood::fleetwood::ProviderConfig;

/// Encrypted payload inside the OAuth2 state parameter.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct StatePayload {
    /// Provider index (position in the providers list).
    #[serde(rename = "p")]
    pub provider_index: i32,
    /// Original callback URL to redirect after auth.
    #[serde(rename = "c")]
    pub callback_url: String,
    /// PKCE code_verifier for the token exchange.
    #[serde(rename = "v")]
    pub code_verifier: String,
    /// Unix timestamp when the state was created.
    #[serde(rename = "t")]
    pub created_at: i64,
}

/// AES-256-GCM codec for OAuth2 state parameters.
///
/// The key is derived from sorted provider client secrets so all instances
/// sharing the same config can encode/decode state — no shared nonce store.
pub struct StateCodec {
    cipher: Aes256Gcm,
    ttl_secs: i64,
}

impl StateCodec {
    /// Create a new StateCodec. Key is SHA-256 of sorted client secrets.
    pub fn new(providers: &[ProviderConfig], ttl_secs: i64) -> Self {
        let mut secrets: Vec<&str> = providers.iter().map(|p| p.client_secret.as_str()).collect();
        secrets.sort();

        let mut hasher = Sha256::new();
        hasher.update(b"identity-state:");
        for s in &secrets {
            hasher.update(s.as_bytes());
        }
        let key = hasher.finalize();

        let cipher = Aes256Gcm::new(&key);
        Self { cipher, ttl_secs }
    }

    /// Encrypt state payload into a URL-safe base64 string.
    pub fn encode(&self, provider_index: i32, callback_url: &str, code_verifier: &str) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let payload = StatePayload {
            provider_index,
            callback_url: callback_url.to_string(),
            code_verifier: code_verifier.to_string(),
            created_at: now,
        };
        let plaintext = serde_json::to_vec(&payload).unwrap();

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let ciphertext = self.cipher.encrypt(&nonce_bytes.into(), plaintext.as_ref()).unwrap();

        // Prepend nonce to ciphertext
        let mut out = nonce_bytes.to_vec();
        out.extend_from_slice(&ciphertext);

        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&out)
    }

    /// Decrypt a state string back into payload. Returns error if invalid or expired.
    pub fn decode(&self, state: &str) -> Result<StatePayload, String> {
        use base64::Engine;

        let data = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(state)
            .map_err(|e| format!("invalid state encoding: {e}"))?;

        if data.len() < 12 {
            return Err("state too short".to_string());
        }

        let nonce_buf: [u8; 12] = data[..12].try_into().unwrap();
        let plaintext = self
            .cipher
            .decrypt(&nonce_buf.into(), &data[12..])
            .map_err(|_| "state decryption failed (tampered or wrong key)".to_string())?;

        let payload: StatePayload =
            serde_json::from_slice(&plaintext).map_err(|e| format!("invalid state payload: {e}"))?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let age = now - payload.created_at;
        if age > self.ttl_secs {
            return Err(format!(
                "state expired (age {age}s, ttl {}s)",
                self.ttl_secs
            ));
        }

        Ok(payload)
    }
}

/// Generate a PKCE code_verifier (43 chars, RFC 7636).
pub fn generate_code_verifier() -> String {
    use base64::Engine;
    let mut b = [0u8; 32];
    OsRng.fill_bytes(&mut b);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

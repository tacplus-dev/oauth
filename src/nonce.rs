use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm,
};
use base64::Engine;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

use oauth_model::types::services::oauth::oauth::ProviderConfig;

use crate::providers::ProviderKey;

/// Encrypted payload inside the OAuth2 state parameter.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct StatePayload {
    /// The provider, by its stable key: its index in the list can name
    /// another provider by the time the IdP answers.
    #[serde(rename = "k")]
    pub provider: ProviderKey,
    /// Original callback URL to redirect after auth.
    #[serde(rename = "c")]
    pub callback_url: String,
    /// PKCE code_verifier for the token exchange.
    #[serde(rename = "v")]
    pub code_verifier: String,
    /// Unix timestamp when the state was created.
    #[serde(rename = "t")]
    pub created_at: i64,
    /// CLI session ID, present when the flow was initiated by operator.
    /// When set, the Callback handler writes the minted token to OAuthState
    /// for delivery to the CLI bidi stream.
    #[serde(rename = "s", default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// First-authorization name relayed by a form_post IDP. Apple sends the
    /// name once, in the POSTed `user` field and never in the id_token, so the
    /// form_post callback seals it into the state for MintCallbackTokens.
    #[serde(rename = "gn", default, skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,
    #[serde(rename = "fn", default, skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,
}

/// AES-256-GCM codec for OAuth2 state parameters.
///
/// The key is derived from the sorted client secrets of the providers it is
/// given (the fleet-wide ones, see `auth::flow_state`), plus the Apple .p8 key
/// when one is configured, so all instances sharing the same config and Secret
/// can encode/decode state — no shared nonce store. The .p8 matters
/// because an Apple provider has no static client secret: its per-exchange
/// minted secret differs per pod and per minute, so it cannot key the state.
pub struct StateCodec {
    cipher: Aes256Gcm,
    ttl_secs: i64,
}

impl StateCodec {
    /// Create a new StateCodec. Key is SHA-256 of sorted client secrets, then
    /// the Apple .p8 PEM if non-empty (an empty one leaves the key unchanged).
    pub fn new(providers: &[ProviderConfig], apple_key_p8: &str, ttl_secs: i64) -> Self {
        let mut secrets: Vec<&str> = providers.iter().map(|p| p.client_secret.as_str()).collect();
        secrets.sort();

        let mut hasher = Sha256::new();
        hasher.update(b"identity-state:");
        for s in &secrets {
            hasher.update(s.as_bytes());
        }
        hasher.update(apple_key_p8.as_bytes());
        let key = hasher.finalize();

        let cipher = Aes256Gcm::new(&key);
        Self { cipher, ttl_secs }
    }

    /// Encrypt state payload into a URL-safe base64 string.
    /// `session_id` is set when the flow was initiated by a CLI client.
    pub fn encode(
        &self,
        provider: &ProviderKey,
        callback_url: &str,
        code_verifier: &str,
        session_id: Option<&str>,
    ) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        self.seal(&StatePayload {
            provider: provider.clone(),
            callback_url: callback_url.to_string(),
            code_verifier: code_verifier.to_string(),
            created_at: now,
            session_id: session_id.map(|s| s.to_string()),
            given_name: None,
            family_name: None,
        })
    }

    /// Encrypt an existing payload as-is, `created_at` included, so re-sealing
    /// a decoded state never extends its lifetime.
    pub fn seal(&self, payload: &StatePayload) -> String {
        let plaintext = serde_json::to_vec(payload).unwrap();

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

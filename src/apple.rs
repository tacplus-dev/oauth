//! Sign in with Apple: the client-secret JWT, and the name Apple sends once.

use base64::Engine;

use oauth_model::types::services::oauth::oauth::AppleSignIn;

/// The client secret's `aud`, fixed by Apple.
const APPLE_AUDIENCE: &str = "https://appleid.apple.com";

/// Lifetime of one minted client secret. Apple accepts up to 6 months, but a
/// secret is minted for every token exchange, so it only has to outlive that
/// one request. Nothing is cached, so there is nothing to re-mint or rotate.
const CLIENT_SECRET_LIFETIME_SECS: i64 = 600;

/// Mints the ES256 client-secret JWT Apple's token endpoint takes in place of a
/// static client_secret.
pub struct AppleClientSecret {
    key: key::keys::ImmutableKey,
    team_id: String,
    services_id: String,
}

impl AppleClientSecret {
    /// `p8_pem` is the PEM text of the .p8 key as Apple issues it (PKCS#8,
    /// P-256). `services_id` is the provider's client_id.
    pub fn new(apple: &AppleSignIn, services_id: &str, p8_pem: &str) -> Result<Self, String> {
        // The chassis key parser takes base64-wrapped PEM.
        let b64_pem = base64::engine::general_purpose::STANDARD.encode(p8_pem.as_bytes());
        let key = key::keys::ImmutableKey::from_pem(apple.key_id.clone(), &b64_pem)
            .map_err(|e| format!("Apple .p8 key: {e}"))?;
        if key.alg() != "ES256" {
            return Err(format!(
                "Apple .p8 key must be a P-256 (ES256) key, got {}",
                key.alg()
            ));
        }
        Ok(Self {
            key,
            team_id: apple.team_id.clone(),
            services_id: services_id.to_string(),
        })
    }

    /// A client secret issued at `now` (unix seconds).
    ///
    /// The JWT is assembled here rather than with the chassis `token::Token`,
    /// whose signer refuses any token without a Schematic `namespace` claim; the
    /// signature itself is the chassis key's.
    pub fn mint(&self, now: i64) -> Result<String, String> {
        let header = serde_json::json!({"alg": "ES256", "kid": self.key.id()});
        let claims = serde_json::json!({
            "iss": self.team_id,
            "sub": self.services_id,
            "aud": APPLE_AUDIENCE,
            "iat": now,
            "exp": now + CLIENT_SECRET_LIFETIME_SECS,
        });
        let b64 = |v: &serde_json::Value| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v.to_string())
        };
        let signing_input = format!("{}.{}", b64(&header), b64(&claims));
        let signature = self
            .key
            .sign(signing_input.as_bytes())
            .map_err(|e| format!("signing Apple client secret: {e}"))?;
        Ok(format!(
            "{signing_input}.{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature)
        ))
    }
}

/// The `user` form field Apple POSTs on the first authorization only:
/// `{"name":{"firstName":"..","lastName":".."},"email":".."}`.
#[derive(serde::Deserialize)]
struct AppleUser {
    name: Option<AppleUserName>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct AppleUserName {
    first_name: Option<String>,
    last_name: Option<String>,
}

/// The (given, family) name from Apple's `user` JSON. Empty parts are `None`.
pub fn parse_user_name(user_json: &str) -> Result<(Option<String>, Option<String>), String> {
    let user: AppleUser =
        serde_json::from_str(user_json).map_err(|e| format!("invalid Apple user JSON: {e}"))?;
    let non_empty = |s: Option<String>| s.filter(|s| !s.is_empty());
    Ok(match user.name {
        Some(n) => (non_empty(n.first_name), non_empty(n.last_name)),
        None => (None, None),
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Fixture P-256 keypair standing in for an Apple .p8 key. Test-only; a
    /// different key from the one the fake Apple signs id_tokens with.
    pub(crate) const TEST_P8_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgYwTfg/yvjlM9jR9F\n\
XmJdM3RO2toUSx/FeNt5nt5hLL2hRANCAAREhlYv84cmU81Pj3jscphXmrNneSeT\n\
+eSRP7uN+GXDoRDiDXKpF2G5GP38PlTt436XKsk3JQOUTfLgmabTmwOV\n\
-----END PRIVATE KEY-----\n";

    pub(crate) const TEST_P8_PUBLIC_PEM: &str = "-----BEGIN PUBLIC KEY-----\n\
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAERIZWL/OHJlPNT4947HKYV5qzZ3kn\n\
k/nkkT+7jfhlw6EQ4g1yqRdhuRj9/D5U7eN+lyrJNyUDlE3y4Jmm05sDlQ==\n\
-----END PUBLIC KEY-----\n";

    /// The chassis verifier for a client secret minted with the fixture .p8.
    pub(crate) fn p8_verifier(key_id: &str) -> jwk::ImmutableJwk {
        let b64 = base64::engine::general_purpose::STANDARD.encode(TEST_P8_PUBLIC_PEM);
        let public = key::keys::ImmutablePublicKey::from_pem(key_id.to_string(), &b64).unwrap();
        jwk::ImmutableJwk::new(jwk::jwk::key_to_jwk(&public).unwrap()).unwrap()
    }

    fn apple() -> AppleSignIn {
        AppleSignIn {
            team_id: "TEAM123456".to_string(),
            key_id: "KEY1234567".to_string(),
            form_post_redirect_uri: "https://console.example/oauth/Auth/BrokerFormPostCallback"
                .to_string(),
            ..Default::default()
        }
    }

    fn segment(jwt: &str, i: usize) -> serde_json::Value {
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(jwt.split('.').nth(i).unwrap())
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    /// The minted secret carries exactly the header and claims Apple requires,
    /// and its signature verifies against the .p8 key's public half through the
    /// chassis verifier — a path independent of the one that signed it.
    #[test]
    fn minted_client_secret_has_apples_shape_and_verifies() {
        let secret = AppleClientSecret::new(&apple(), "com.example.services", TEST_P8_PEM)
            .expect("a PKCS#8 P-256 key is a valid .p8");
        let jwt = secret.mint(1_760_000_000).unwrap();

        assert_eq!(
            segment(&jwt, 0),
            serde_json::json!({"alg": "ES256", "kid": "KEY1234567"})
        );
        assert_eq!(
            segment(&jwt, 1),
            serde_json::json!({
                "iss": "TEAM123456",
                "sub": "com.example.services",
                "aud": "https://appleid.apple.com",
                "iat": 1_760_000_000,
                "exp": 1_760_000_600,
            })
        );

        // Verified as of now, so mint with a current iat.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let jwt = secret.mint(now).unwrap();
        token::Token::parse(&jwt)
            .unwrap()
            .verify(&p8_verifier("KEY1234567"))
            .expect("the client secret must verify against the .p8 public key");
    }

    /// Apple's lifetime cap is 6 months; a per-exchange secret stays far inside it.
    #[test]
    fn client_secret_lifetime_is_within_apples_six_month_cap() {
        assert!(CLIENT_SECRET_LIFETIME_SECS > 0);
        assert!(CLIENT_SECRET_LIFETIME_SECS <= 15_777_000);
    }

    /// A key Apple could not have issued is refused when the provider is built,
    /// not discovered at the first sign-in.
    #[test]
    fn non_p256_and_garbage_keys_are_refused() {
        let ed = key::keys::generate_ed25519_key().unwrap();
        let ed_pem = std::str::from_utf8(ed.pem_bytes()).unwrap();
        let err = AppleClientSecret::new(&apple(), "svc", ed_pem)
            .err()
            .expect("an Ed25519 key is not a .p8");
        assert!(err.contains("ES256"), "got {err}");

        assert!(AppleClientSecret::new(&apple(), "svc", "not a pem").is_err());
        assert!(AppleClientSecret::new(&apple(), "svc", "").is_err());
    }

    #[test]
    fn first_authorization_name_is_parsed() {
        let user = r#"{"name":{"firstName":"Ada","lastName":"Lovelace"},"email":"x@privaterelay.appleid.com"}"#;
        assert_eq!(
            parse_user_name(user).unwrap(),
            (Some("Ada".to_string()), Some("Lovelace".to_string()))
        );
    }

    /// The user may share no name, or only part of one.
    #[test]
    fn missing_or_empty_name_parts_are_none() {
        assert_eq!(parse_user_name(r#"{"email":"a@b.c"}"#).unwrap(), (None, None));
        assert_eq!(
            parse_user_name(r#"{"name":{"firstName":"","lastName":"Solo"}}"#).unwrap(),
            (None, Some("Solo".to_string()))
        );
        assert!(parse_user_name("not json").is_err());
    }
}

//! Auth.SendSignInLink and Auth.MintSignInLinkTokens: sign-in by emailed link.
//!
//! oauth holds no token. Kernel issues it (Mint.CreateSignInLink), keeps only
//! its hash, and spends it once when MintUserToken presents it as an
//! AUTH_BROKER_KIND_EMAIL_LINK proof, on whichever kernel node the call lands.
//! The mail goes out through mailbox (SignInMail.SendSignInMail, the Gmail
//! adapter), never through a mail client here. What is left to oauth is what it
//! does for an IdP login: the callback allowlist, the per-address limit, and
//! turning kernel's tokens into the CallbackResponse the webapp already handles.
//!
//! LOGGING. The token and the link are credentials and are never logged; an
//! address is logged by its domain only, as ClassifySignInEmail does.

use std::time::Instant;

use tracing::{info, warn};

use oauth_model::s2sm::ServiceManager;
use oauth_model::types::services::kernel::kernel::{CreateSignInLinkRequest, CreateSignInLinkResponse};
use oauth_model::types::services::mailbox::mailbox::SendSignInMailRequest;
use oauth_model::types::services::oauth::oauth::{
    CallbackResponse, MintSignInLinkTokensRequest, ProviderConfig, SendSignInLinkRequest,
    SendSignInLinkResponse,
};
use oauth_model::types::sys::tokenrequest::tokenrequest::{
    AuthBrokerKind, MintUserTokenRequest, TokenMintResponse,
};

use crate::auth::{callback_response, callback_url_allowed};
use crate::signin_email::EmailRateLimiter;

/// The query parameter the token rides in on the mailed link.
pub const LINK_PARAM: &str = "sign_in_link";

/// The three calls a sign-in link makes. A trait so the tests can stand in for
/// kernel and mailbox; the service uses the ServiceManager's generated clients.
#[tonic::async_trait]
pub trait SignInLinkPorts: Send + Sync {
    async fn create_sign_in_link(&self, req: CreateSignInLinkRequest) -> Result<CreateSignInLinkResponse, tonic::Status>;
    async fn send_sign_in_mail(&self, req: SendSignInMailRequest) -> Result<(), tonic::Status>;
    async fn mint_user_token(&self, req: MintUserTokenRequest) -> Result<TokenMintResponse, tonic::Status>;
}

#[tonic::async_trait]
impl SignInLinkPorts for ServiceManager {
    async fn create_sign_in_link(&self, req: CreateSignInLinkRequest) -> Result<CreateSignInLinkResponse, tonic::Status> {
        Ok(self.s2s().kernel().mint_client().create_sign_in_link(req).await?.into_inner())
    }

    async fn send_sign_in_mail(&self, req: SendSignInMailRequest) -> Result<(), tonic::Status> {
        self.s2s().mailbox().sign_in_mail_client().send_sign_in_mail(req).await?;
        Ok(())
    }

    async fn mint_user_token(&self, req: MintUserTokenRequest) -> Result<TokenMintResponse, tonic::Status> {
        Ok(self.s2s().kernel().mint_client().mint_user_token(req).await?.into_inner())
    }
}

/// A sign-in link may lead only where an IdP login may: a callback_url some
/// enabled provider's allowed_redirect_uri_prefixes covers, by the same rule
/// Authorize applies to one provider.
fn callback_allowed(providers: &[ProviderConfig], callback_url: &str) -> Result<(), tonic::Status> {
    if providers
        .iter()
        .any(|p| p.enable && callback_url_allowed(&p.allowed_redirect_uri_prefixes, callback_url))
    {
        return Ok(());
    }
    warn!(callback_url = %callback_url, "sign-in link callback_url is not in any provider's redirect allowlist");
    Err(tonic::Status::invalid_argument("callback_url is not permitted"))
}

/// The address's domain, the only part of it that is logged.
fn domain(email: &str) -> &str {
    email.rsplit_once('@').map_or("", |(_, d)| d)
}

/// Mail `req.email` a link to `req.callback_url` carrying a fresh kernel token.
///
/// Checks come before kernel is asked for anything, so a refused request
/// creates no token and sends no mail.
pub async fn send(
    ports: &dyn SignInLinkPorts,
    limiter: &EmailRateLimiter,
    providers: &[ProviderConfig],
    req: SendSignInLinkRequest,
) -> Result<SendSignInLinkResponse, tonic::Status> {
    if !limiter.allow(&req.email, Instant::now()) {
        return Err(tonic::Status::resource_exhausted(
            "too many sign-in links for this address, try again in a minute",
        ));
    }
    callback_allowed(providers, &req.callback_url)?;

    let link = ports
        .create_sign_in_link(CreateSignInLinkRequest {
            email: req.email.clone(),
            trace_id: req.trace_id.clone(),
            ..Default::default()
        })
        .await
        .map_err(|e| {
            warn!(code = ?e.code(), error = %e.message(), "kernel CreateSignInLink failed");
            tonic::Status::internal("could not create a sign-in link")
        })?;

    let query = serde_urlencoded::to_string([(LINK_PARAM, link.token.as_str())]).unwrap_or_default();
    let separator = if req.callback_url.contains('?') { '&' } else { '?' };
    ports
        .send_sign_in_mail(SendSignInMailRequest {
            to: req.email.clone(),
            link: format!("{}{separator}{query}", req.callback_url),
            expires_in_seconds: link.expires_in_seconds,
            trace_id: req.trace_id.clone(),
            ..Default::default()
        })
        .await
        .map_err(|e| {
            warn!(code = ?e.code(), error = %e.message(), "mailbox SendSignInMail failed");
            tonic::Status::unavailable("could not send the sign-in mail")
        })?;

    info!(domain = %domain(&req.email), "sign-in link mailed");
    Ok(SendSignInLinkResponse::default())
}

/// Spend `req.token` at kernel and answer with the session, as
/// MintCallbackTokens does for an IdP login.
pub async fn mint(
    ports: &dyn SignInLinkPorts,
    providers: &[ProviderConfig],
    req: MintSignInLinkTokensRequest,
) -> Result<CallbackResponse, tonic::Status> {
    callback_allowed(providers, &req.callback_url)?;

    // No subject and no claims: on the EMAIL_LINK arm kernel takes both from the
    // link it issued, never from the broker.
    let mint_resp = ports
        .mint_user_token(MintUserTokenRequest {
            broker_kind: AuthBrokerKind::EmailLink as i32,
            proof_token: req.token,
            trace_id: req.trace_id.clone(),
            ..Default::default()
        })
        .await
        .map_err(|e| match e.code() {
            // An unknown, spent or expired link, a disabled person, paused
            // sign-ups: the caller's answer, said as kernel said it.
            tonic::Code::Unauthenticated | tonic::Code::PermissionDenied | tonic::Code::ResourceExhausted => {
                info!(code = ?e.code(), error = %e.message(), "sign-in link refused by kernel");
                tonic::Status::new(e.code(), e.message().to_string())
            }
            _ => {
                warn!(code = ?e.code(), error = %e.message(), "kernel MintUserToken for a sign-in link failed");
                tonic::Status::internal("sign-in link mint failed")
            }
        })?;

    info!("sign-in link spent (delegated to kernel)");
    Ok(callback_response(&mint_resp, req.callback_url))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    use oauth_model::types::sys::token::token::Token;

    const TOKEN: &str = "c2lnbi1pbi1saW5rLXRva2VuLWZvci10ZXN0cy0wMDAwMDA";
    const CALLBACK: &str = "https://app.example.com/signin/callback";

    /// Stands in for kernel and mailbox: issues TOKEN, records every mail, and
    /// spends TOKEN once — the single-use kernel enforces — answering
    /// UNAUTHENTICATED after that, as kernel does for a spent link.
    #[derive(Default)]
    struct FakePorts {
        created: Mutex<Vec<String>>,
        mailed: Mutex<Vec<SendSignInMailRequest>>,
        minted: Mutex<Vec<MintUserTokenRequest>>,
        spent: Mutex<bool>,
    }

    fn token_proto(base64: &str, exp_in: i64) -> Token {
        let exp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            + exp_in;
        Token {
            base64: base64.to_string(),
            payload: [("exp".to_string(), exp.to_string())].into_iter().collect(),
            ..Default::default()
        }
    }

    #[tonic::async_trait]
    impl SignInLinkPorts for FakePorts {
        async fn create_sign_in_link(&self, req: CreateSignInLinkRequest) -> Result<CreateSignInLinkResponse, tonic::Status> {
            self.created.lock().unwrap().push(req.email);
            Ok(CreateSignInLinkResponse { token: TOKEN.to_string(), expires_in_seconds: 900, ..Default::default() })
        }

        async fn send_sign_in_mail(&self, req: SendSignInMailRequest) -> Result<(), tonic::Status> {
            self.mailed.lock().unwrap().push(req);
            Ok(())
        }

        async fn mint_user_token(&self, req: MintUserTokenRequest) -> Result<TokenMintResponse, tonic::Status> {
            self.minted.lock().unwrap().push(req.clone());
            let mut spent = self.spent.lock().unwrap();
            if req.proof_token != TOKEN || *spent {
                return Err(tonic::Status::unauthenticated("sign-in link is unknown, used or expired"));
            }
            *spent = true;
            Ok(TokenMintResponse {
                refresh_token: Some(token_proto("refresh-jwt", 86_400)),
                access_token: Some(token_proto("access-jwt", 3_600)),
                ..Default::default()
            })
        }
    }

    fn providers() -> Vec<ProviderConfig> {
        vec![
            ProviderConfig {
                enable: true,
                name: "google".to_string(),
                allowed_redirect_uri_prefixes: vec!["https://app.example.com/signin/".to_string()],
                ..Default::default()
            },
            ProviderConfig {
                enable: false,
                name: "disabled".to_string(),
                allowed_redirect_uri_prefixes: vec!["https://disabled.example.com/".to_string()],
                ..Default::default()
            },
        ]
    }

    fn send_req(email: &str, callback_url: &str) -> SendSignInLinkRequest {
        SendSignInLinkRequest {
            email: email.to_string(),
            callback_url: callback_url.to_string(),
            ..Default::default()
        }
    }

    fn mint_req(token: &str) -> MintSignInLinkTokensRequest {
        MintSignInLinkTokensRequest {
            token: token.to_string(),
            callback_url: CALLBACK.to_string(),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn the_mail_carries_the_kernel_token_on_the_allowlisted_callback() {
        let ports = FakePorts::default();
        send(&ports, &EmailRateLimiter::new(), &providers(), send_req("pat@selfhosted.example", CALLBACK))
            .await
            .unwrap();
        {
            let mailed = ports.mailed.lock().unwrap();
            assert_eq!(mailed.len(), 1);
            assert_eq!(mailed[0].to, "pat@selfhosted.example");
            assert_eq!(mailed[0].link, format!("{CALLBACK}?sign_in_link={TOKEN}"));
            assert_eq!(mailed[0].expires_in_seconds, 900);
        }

        // A callback that already has a query keeps it.
        send(&ports, &EmailRateLimiter::new(), &providers(), send_req("pat@selfhosted.example", &format!("{CALLBACK}?next=%2Fhome")))
            .await
            .unwrap();
        assert_eq!(
            ports.mailed.lock().unwrap()[1].link,
            format!("{CALLBACK}?next=%2Fhome&sign_in_link={TOKEN}")
        );
    }

    #[tokio::test]
    async fn a_callback_outside_every_allowlist_is_refused_before_kernel_or_mail() {
        for url in [
            "https://evil.example.com/signin/callback",
            "https://app.example.com/signin-evil/callback",
            // Only an ENABLED provider's list counts.
            "https://disabled.example.com/callback",
        ] {
            let ports = FakePorts::default();
            let err = send(&ports, &EmailRateLimiter::new(), &providers(), send_req("pat@selfhosted.example", url))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument, "{url}");
            assert!(ports.created.lock().unwrap().is_empty(), "{url}: no token may be created");
            assert!(ports.mailed.lock().unwrap().is_empty(), "{url}: no mail may be sent");
        }
    }

    #[tokio::test]
    async fn one_address_is_limited_and_another_is_not() {
        let ports = FakePorts::default();
        let limiter = EmailRateLimiter::new();
        for i in 0..5 {
            send(&ports, &limiter, &providers(), send_req("pat@selfhosted.example", CALLBACK))
                .await
                .unwrap_or_else(|e| panic!("send {i} is inside the burst: {e}"));
        }
        let err = send(&ports, &limiter, &providers(), send_req("PAT@selfhosted.example", CALLBACK))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::ResourceExhausted);
        assert_eq!(ports.mailed.lock().unwrap().len(), 5, "the limited send mails nothing");
        send(&ports, &limiter, &providers(), send_req("sam@selfhosted.example", CALLBACK))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn the_link_mints_the_same_session_shape_as_the_idp_callback_once() {
        let ports = FakePorts::default();
        let resp = mint(&ports, &providers(), mint_req(TOKEN)).await.unwrap();
        assert_eq!(resp.refresh_token, "refresh-jwt");
        assert_eq!(resp.access_token, "access-jwt");
        assert_eq!(resp.callback_url, CALLBACK);
        assert!((3_590..=3_600).contains(&resp.access_token_expires_in));
        assert!((86_390..=86_400).contains(&resp.refresh_token_expires_in));

        let minted = ports.minted.lock().unwrap()[0].clone();
        assert_eq!(minted.broker_kind, AuthBrokerKind::EmailLink as i32);
        assert_eq!(minted.proof_token, TOKEN);
        assert!(minted.subject.is_empty() && minted.claims.is_none(), "kernel names the person, not oauth");

        // The second spend is refused, and refused as UNAUTHENTICATED.
        let err = mint(&ports, &providers(), mint_req(TOKEN)).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn a_mint_for_a_callback_outside_the_allowlist_never_reaches_kernel() {
        let ports = FakePorts::default();
        let mut req = mint_req(TOKEN);
        req.callback_url = "https://evil.example.com/".to_string();
        assert_eq!(mint(&ports, &providers(), req).await.unwrap_err().code(), tonic::Code::InvalidArgument);
        assert!(ports.minted.lock().unwrap().is_empty());
    }

    /// Everything the send and mint paths log, in one buffer.
    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn no_token_link_or_address_is_logged() {
        let captured = Captured::default();
        let writer = captured.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(move || writer.clone())
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let ports = FakePorts::default();
        let limiter = EmailRateLimiter::new();
        send(&ports, &limiter, &providers(), send_req("pat@selfhosted.example", CALLBACK)).await.unwrap();
        send(&ports, &limiter, &providers(), send_req("pat@selfhosted.example", "https://evil.example.com/")).await.unwrap_err();
        mint(&ports, &providers(), mint_req(TOKEN)).await.unwrap();
        mint(&ports, &providers(), mint_req(TOKEN)).await.unwrap_err();

        let logs = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
        assert!(logs.contains("sign-in link mailed"), "the capture saw the send path: {logs}");
        assert!(logs.contains("sign-in link refused by kernel"), "the capture saw the reuse: {logs}");
        assert!(!logs.contains(TOKEN), "a token was logged: {logs}");
        assert!(!logs.contains("pat@"), "an address was logged: {logs}");
    }
}

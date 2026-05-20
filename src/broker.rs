//! BrokerHandle manages the bidi stream to kernel's CliTokenBroker service.
//!
//! On startup, opens a BrokerStream to kernel and sends Register with the
//! oauth instance's instance_id. When CLI sessions start, register_nonce()
//! records the nonce and returns a oneshot::Receiver for token delivery.
//! When browser auth completes, complete_nonce() forwards the authenticated
//! identity to kernel for matching and token minting.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, RwLock};
use tonic::transport::Channel;
use tracing::{info, warn, error};

use crate::types::services::kernel::kernel::{
    CliTokenBrokerRequest, CliTokenBrokerResponse,
    cli_token_broker_request, cli_token_broker_response,
    CliTokenBrokerRegister, CliTokenBrokerRegisterNonce,
    CliTokenBrokerCompleteNonce, CliTokenBrokerTokenDelivery,
    cli_token_broker_service_client::CliTokenBrokerServiceClient,
};

/// Handle for interacting with the kernel CLI token broker.
#[derive(Clone)]
pub struct BrokerHandle {
    tx: mpsc::Sender<CliTokenBrokerRequest>,
    pending: Arc<RwLock<HashMap<String, oneshot::Sender<String>>>>,
}

impl BrokerHandle {
    /// Spawn the broker stream connection to kernel.
    /// Returns a BrokerHandle for registering nonces and completing auth.
    pub async fn start(
        channel: Channel,
        instance_id: String,
        token_provider: impl Fn() -> futures::future::BoxFuture<'static, Result<String, Box<dyn std::error::Error + Send + Sync>>> + Send + Sync + 'static,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let pending: Arc<RwLock<HashMap<String, oneshot::Sender<String>>>> =
            Arc::new(RwLock::new(HashMap::new()));

        let (tx, mut rx) = mpsc::channel::<CliTokenBrokerRequest>(32);

        let pending_clone = Arc::clone(&pending);
        let instance_id_clone = instance_id.clone();
        let tx_clone = tx.clone();

        tokio::spawn(async move {
            loop {
                match Self::run_stream(
                    channel.clone(),
                    &instance_id_clone,
                    &mut rx,
                    &pending_clone,
                    &token_provider,
                ).await {
                    Ok(()) => {
                        info!("BrokerStream closed cleanly");
                        break;
                    }
                    Err(e) => {
                        warn!(error = %e, "BrokerStream disconnected, reconnecting in 5s");
                        // Fail all pending nonces on disconnect
                        {
                            let mut map = pending_clone.write().await;
                            for (nonce, sender) in map.drain() {
                                let _ = sender.send(String::new()); // empty = failed
                                warn!(nonce = %&nonce[..8], "nonce failed due to broker disconnect");
                            }
                        }
                        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                    }
                }
            }
        });

        // Send initial Register message
        tx.send(CliTokenBrokerRequest {
            msg: Some(cli_token_broker_request::Msg::Register(
                CliTokenBrokerRegister {
                    instance_id: instance_id.clone(),
                    ..Default::default()
                },
            )),
            ..Default::default()
        })
        .await
        .map_err(|e| format!("failed to send Register: {e}"))?;

        info!(instance_id = %instance_id, "BrokerHandle started");

        Ok(Self { tx, pending })
    }

    async fn run_stream(
        channel: Channel,
        instance_id: &str,
        rx: &mut mpsc::Receiver<CliTokenBrokerRequest>,
        pending: &Arc<RwLock<HashMap<String, oneshot::Sender<String>>>>,
        token_provider: &(impl Fn() -> futures::future::BoxFuture<'static, Result<String, Box<dyn std::error::Error + Send + Sync>>> + Send + Sync),
    ) -> Result<(), Box<dyn std::error::Error>> {
        let token = (token_provider)().await?;
        let mut client = CliTokenBrokerServiceClient::new(channel);

        let outbound = async_stream::stream! {
            while let Some(msg) = rx.recv().await {
                yield msg;
            }
        };

        let mut request = tonic::Request::new(outbound);
        request.metadata_mut().insert(
            "authorization",
            format!("Bearer {}", token).parse()?,
        );

        let response = client.broker_stream(request).await?;
        let mut inbound = response.into_inner();

        while let Some(msg) = inbound.message().await? {
            match msg.msg {
                Some(cli_token_broker_response::Msg::TokenDelivery(delivery)) => {
                    let nonce = delivery.nonce.clone();
                    let mut map = pending.write().await;
                    if let Some(sender) = map.remove(&nonce) {
                        let _ = sender.send(delivery.refresh_token);
                        info!(nonce = %&nonce[..8.min(nonce.len())], "token delivered to CLI session");
                    } else {
                        warn!(nonce = %&nonce[..8.min(nonce.len())], "token delivery for unknown nonce");
                    }
                }
                Some(cli_token_broker_response::Msg::Error(err)) => {
                    let nonce = err.nonce.clone();
                    let mut map = pending.write().await;
                    if let Some(sender) = map.remove(&nonce) {
                        let _ = sender.send(String::new()); // empty = error
                        warn!(nonce = %&nonce[..8.min(nonce.len())], message = %err.message, "broker error");
                    }
                }
                _ => {}
            }
        }

        Ok(())
    }

    /// Register a nonce for a pending CLI session.
    /// Returns a oneshot::Receiver that will receive the minted refresh token.
    pub async fn register_nonce(&self, nonce: &str) -> Result<oneshot::Receiver<String>, tonic::Status> {
        let (reply_tx, reply_rx) = oneshot::channel();

        {
            let mut map = self.pending.write().await;
            map.insert(nonce.to_string(), reply_tx);
        }

        self.tx
            .send(CliTokenBrokerRequest {
                msg: Some(cli_token_broker_request::Msg::RegisterNonce(
                    CliTokenBrokerRegisterNonce {
                        nonce: nonce.to_string(),
                        ..Default::default()
                    },
                )),
                ..Default::default()
            })
            .await
            .map_err(|e| {
                tonic::Status::internal(format!("broker channel closed: {e}"))
            })?;

        Ok(reply_rx)
    }

    /// Complete a nonce with the authenticated user identity.
    /// Called after browser auth (Callback or CompleteCliAuth).
    pub async fn complete_nonce(
        &self,
        nonce: &str,
        subject: &str,
        claims: Option<prost_wkt_types::Struct>,
    ) -> Result<(), tonic::Status> {
        self.tx
            .send(CliTokenBrokerRequest {
                msg: Some(cli_token_broker_request::Msg::CompleteNonce(
                    CliTokenBrokerCompleteNonce {
                        nonce: nonce.to_string(),
                        subject: subject.to_string(),
                        claims,
                        ..Default::default()
                    },
                )),
                ..Default::default()
            })
            .await
            .map_err(|e| {
                tonic::Status::internal(format!("broker channel closed: {e}"))
            })
    }
}

//! BrokerHandle manages the bidi stream to kernel's CliTokenBroker service.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, RwLock};
use tonic::transport::Channel;
use tracing::{info, warn};

use oauth_tacplus::types::services::kernel::kernel::{
    CliTokenBrokerRequest, CliTokenBrokerResponse,
    cli_token_broker_request, cli_token_broker_response,
    CliTokenBrokerRegister, CliTokenBrokerRegisterNonce,
    CliTokenBrokerCompleteNonce,
    cli_token_broker_client::CliTokenBrokerClient,
};

/// Handle for interacting with the kernel CLI token broker.
#[derive(Clone)]
pub struct BrokerHandle {
    tx: mpsc::Sender<CliTokenBrokerRequest>,
    pending: Arc<RwLock<HashMap<String, oneshot::Sender<String>>>>,
}

impl BrokerHandle {
    /// Spawn the broker stream connection to kernel.
    pub async fn start(
        channel: Channel,
        instance_id: String,
        service_token: String,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let pending: Arc<RwLock<HashMap<String, oneshot::Sender<String>>>> =
            Arc::new(RwLock::new(HashMap::new()));

        let (tx, rx) = mpsc::channel::<CliTokenBrokerRequest>(32);

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

        let pending_clone = Arc::clone(&pending);

        // Spawn the bidi stream handler
        tokio::spawn(async move {
            info!("broker: opening BrokerStream to kernel");
            let outbound = tokio_stream::wrappers::ReceiverStream::new(rx);

            let mut request = tonic::Request::new(outbound);
            if let Ok(val) = format!("Bearer {}", service_token).parse() {
                request.metadata_mut().insert("authorization", val);
            }

            let mut client = CliTokenBrokerClient::new(channel);
            info!("broker: calling broker_stream RPC");
            match client.broker_stream(request).await {
                Ok(response) => {
                    let mut inbound = response.into_inner();
                    use tokio_stream::StreamExt;
                    while let Some(msg) = inbound.next().await {
                        match msg {
                            Ok(resp) => match resp.msg {
                                Some(cli_token_broker_response::Msg::TokenDelivery(delivery)) => {
                                    let nonce = delivery.nonce.clone();
                                    let mut map = pending_clone.write().await;
                                    if let Some(sender) = map.remove(&nonce) {
                                        let _ = sender.send(delivery.refresh_token);
                                        info!(nonce = %&nonce[..8.min(nonce.len())], "token delivered to CLI session");
                                    } else {
                                        warn!(nonce = %&nonce[..8.min(nonce.len())], "token delivery for unknown nonce");
                                    }
                                }
                                Some(cli_token_broker_response::Msg::Error(err)) => {
                                    let nonce = err.nonce.clone();
                                    let mut map = pending_clone.write().await;
                                    if let Some(sender) = map.remove(&nonce) {
                                        let _ = sender.send(String::new());
                                        warn!(nonce = %&nonce[..8.min(nonce.len())], message = %err.message, "broker error");
                                    }
                                }
                                _ => {}
                            },
                            Err(e) => {
                                warn!(error = %e, "broker stream error");
                                break;
                            }
                        }
                    }
                    info!("broker stream closed");
                }
                Err(e) => {
                    warn!(error = %e, "failed to open broker stream");
                }
            }

            // Fail all pending nonces on disconnect
            let mut map = pending_clone.write().await;
            for (_nonce, sender) in map.drain() {
                let _ = sender.send(String::new());
            }
        });

        info!(instance_id = %instance_id, "BrokerHandle started");

        Ok(Self { tx, pending })
    }

    /// Register a nonce for a pending CLI session.
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

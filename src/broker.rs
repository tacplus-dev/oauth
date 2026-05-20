//! BrokerHandle manages the bidi stream to kernel's CliTokenBroker service.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot, RwLock};
use tracing::{info, warn};

use oauth_tacplus::s2sm::ServiceManager;
use oauth_tacplus::types::services::kernel::kernel::{
    CliTokenBrokerRequest, CliTokenBrokerResponse,
    cli_token_broker_request, cli_token_broker_response,
    CliTokenBrokerRegister, CliTokenBrokerRegisterNonce,
    CliTokenBrokerCompleteNonce,
};

/// Handle for interacting with the kernel CLI token broker.
#[derive(Clone)]
pub struct BrokerHandle {
    tx: mpsc::Sender<CliTokenBrokerRequest>,
    pending: Arc<RwLock<HashMap<String, oneshot::Sender<String>>>>,
}

impl BrokerHandle {
    /// Spawn the broker stream connection to kernel via the ServiceManager's S2S client.
    pub fn start(sm: Arc<ServiceManager>, instance_id: String) -> Self {
        let pending: Arc<RwLock<HashMap<String, oneshot::Sender<String>>>> =
            Arc::new(RwLock::new(HashMap::new()));

        let (tx, mut rx) = mpsc::channel::<CliTokenBrokerRequest>(32);
        let pending_clone = Arc::clone(&pending);
        let instance_id_owned = instance_id.clone();

        // Spawn the broker stream with reconnect loop
        tokio::spawn(async move {
            let instance_id = instance_id_owned;
            // Send initial Register as the first message once the stream opens
            let register_msg = CliTokenBrokerRequest {
                msg: Some(cli_token_broker_request::Msg::Register(
                    CliTokenBrokerRegister {
                        instance_id: instance_id.clone(),
                        ..Default::default()
                    },
                )),
                ..Default::default()
            };

            loop {
                info!(instance_id = %instance_id, "broker: connecting to kernel CliTokenBroker");

                match Self::run_stream(&sm, register_msg.clone(), &mut rx, &pending_clone).await {
                    Ok(()) => {
                        info!("broker: stream closed cleanly");
                        break;
                    }
                    Err(e) => {
                        warn!(error = %e, "broker: stream failed, reconnecting in 5s");
                        // Fail all pending nonces
                        {
                            let mut map = pending_clone.write().await;
                            for (_nonce, sender) in map.drain() {
                                let _ = sender.send(String::new());
                            }
                        }
                        tokio::time::sleep(Duration::from_secs(5)).await;
                    }
                }
            }
        });

        info!(instance_id = %instance_id, "BrokerHandle created");

        Self { tx, pending }
    }

    async fn run_stream(
        sm: &ServiceManager,
        register_msg: CliTokenBrokerRequest,
        rx: &mut mpsc::Receiver<CliTokenBrokerRequest>,
        pending: &Arc<RwLock<HashMap<String, oneshot::Sender<String>>>>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Use the SM's S2S client infrastructure (handles TLS, auth, routing)
        let client = sm.grpc_clients().services().cli_token_broker_client();

        // Build the outbound stream: register first, then forward from the channel
        let (stream_tx, stream_rx) = mpsc::channel::<CliTokenBrokerRequest>(32);

        // Send Register as first message
        stream_tx.send(register_msg).await?;

        // Spawn a forwarder from the main tx channel to the stream tx
        let stream_tx_clone = stream_tx.clone();
        tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                if stream_tx_clone.send(msg).await.is_err() {
                    break; // stream closed
                }
            }
        });

        let outbound = tokio_stream::wrappers::ReceiverStream::new(stream_rx);
        let response = client.broker_stream(outbound).await?;
        let mut inbound = response.into_inner();

        info!("broker: stream opened");

        use tokio_stream::StreamExt;
        while let Some(msg) = inbound.next().await {
            match msg {
                Ok(resp) => match resp.msg {
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
                            let _ = sender.send(String::new());
                            warn!(nonce = %&nonce[..8.min(nonce.len())], message = %err.message, "broker error");
                        }
                    }
                    _ => {}
                },
                Err(e) => {
                    return Err(format!("stream error: {e}").into());
                }
            }
        }

        Ok(())
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

//! BrokerHandle manages the bidi stream to kernel's CliTokenBroker service.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot, RwLock};
use tokio_stream::StreamExt;
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
    pub fn start(sm: Arc<ServiceManager>, instance_id: String) -> Self {
        let pending: Arc<RwLock<HashMap<String, oneshot::Sender<String>>>> =
            Arc::new(RwLock::new(HashMap::new()));

        // tx/rx lives for the lifetime of the handle.
        // The spawned task reads from rx and forwards to kernel.
        // On reconnect, a new gRPC stream is opened but tx/rx stays the same.
        let (tx, rx) = mpsc::channel::<CliTokenBrokerRequest>(32);
        let pending_clone = Arc::clone(&pending);
        let instance_id_clone = instance_id.clone();

        tokio::spawn(async move {
            Self::stream_loop(sm, instance_id_clone, rx, pending_clone).await;
        });

        info!(instance_id = %instance_id, "BrokerHandle created");
        Self { tx, pending }
    }

    /// Reconnecting stream loop. Opens the bidi stream to kernel, forwards
    /// messages from rx, and receives token deliveries. On disconnect,
    /// retries after a delay.
    async fn stream_loop(
        sm: Arc<ServiceManager>,
        instance_id: String,
        mut rx: mpsc::Receiver<CliTokenBrokerRequest>,
        pending: Arc<RwLock<HashMap<String, oneshot::Sender<String>>>>,
    ) {
        loop {
            info!(instance_id = %instance_id, "broker: connecting to kernel");

            // Open the stream with Register as the first message.
            let client = sm.grpc_clients().services().cli_token_broker_client();

            let register_msg = CliTokenBrokerRequest {
                msg: Some(cli_token_broker_request::Msg::Register(
                    CliTokenBrokerRegister {
                        instance_id: instance_id.clone(),
                        ..Default::default()
                    },
                )),
                ..Default::default()
            };

            // Outbound: a channel that we control. We send Register first,
            // then forward messages from rx.
            let (stream_tx, stream_rx) = mpsc::channel::<CliTokenBrokerRequest>(32);
            if stream_tx.send(register_msg).await.is_err() {
                warn!("broker: failed to send Register");
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }

            let outbound = tokio_stream::wrappers::ReceiverStream::new(stream_rx);

            let response = match client.broker_stream(outbound).await {
                Ok(r) => r,
                Err(e) => {
                    warn!(error = %e, "broker: failed to open stream");
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    continue;
                }
            };

            info!("broker: stream opened");
            let mut inbound = response.into_inner();

            // Run the stream: forward rx → stream_tx, read inbound → pending
            loop {
                tokio::select! {
                    // Forward user messages to the gRPC stream
                    msg = rx.recv() => {
                        match msg {
                            Some(m) => {
                                if stream_tx.send(m).await.is_err() {
                                    warn!("broker: outbound stream closed");
                                    break;
                                }
                            }
                            None => {
                                // tx dropped — handle is gone, shut down
                                info!("broker: handle dropped, shutting down");
                                return;
                            }
                        }
                    }
                    // Receive responses from kernel
                    msg = inbound.next() => {
                        match msg {
                            Some(Ok(resp)) => Self::handle_response(resp, &pending).await,
                            Some(Err(e)) => {
                                warn!(error = %e, "broker: stream error");
                                break;
                            }
                            None => {
                                info!("broker: stream ended");
                                break;
                            }
                        }
                    }
                }
            }

            // Fail pending nonces on disconnect
            {
                let mut map = pending.write().await;
                for (_nonce, sender) in map.drain() {
                    let _ = sender.send(String::new());
                }
            }

            warn!("broker: disconnected, reconnecting in 5s");
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    }

    async fn handle_response(
        resp: CliTokenBrokerResponse,
        pending: &Arc<RwLock<HashMap<String, oneshot::Sender<String>>>>,
    ) {
        match resp.msg {
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
        }
    }

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
            .map_err(|e| tonic::Status::internal(format!("broker channel closed: {e}")))?;
        Ok(reply_rx)
    }

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
            .map_err(|e| tonic::Status::internal(format!("broker channel closed: {e}")))
    }
}

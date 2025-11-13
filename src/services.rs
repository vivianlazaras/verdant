use keycast::discovery::{Beacon, Discovery, ServiceIdent, WaitFor};
use crate::api::APIClient;
use crate::auth::LoginResult;
use crate::server::auth::LoginResponse;
use crate::livekit::TokenResponse;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
pub struct ServiceState {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VerdantUiCmd {
    LoginResult(LoginResult),
    /// this variant is in both [`VerdantUiCmd`] and in [`VerdantCmd`] because it can result
    /// from the background service through mdns_sd, and through the user manually entering needed information.
    ServerDiscovered(Discovery),
    LkToken(TokenResponse),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRequest {
    url: String,
    username: String,
    password: String,
}

impl LoginRequest {
    pub fn new(
        url: impl Into<String>,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        Self {
            username: username.into(),
            url: url.into(),
            password: password.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VerdantCmd {
    Login(LoginRequest),
    /// this variant is in both [`VerdantUiCmd`] and in [`VerdantCmd`] because it can result
    /// from the background service through mdns_sd, and through the user manually entering needed information.
    ServerDiscovered(Discovery),
}

// for now empty but will hold ongoing [`Discovery`]
pub struct VerdantService {
    handle: tokio::runtime::Handle,
    discovery_handle: Option<tokio::task::JoinHandle<()>>,
    service_handle: tokio::task::JoinHandle<()>,
    discovered: Vec<Discovery>,
    cmd_tx: mpsc::UnboundedSender<VerdantCmd>,
    ui_rx: mpsc::UnboundedReceiver<VerdantUiCmd>,
}

async fn discover(service: &str) -> Result<Vec<Discovery>, keycast::errors::BeaconError> {
    let ident = ServiceIdent::TCP(service.to_string());

    let beacons = Beacon::discover(ident, WaitFor::FirstDiscovery, None).await?;
    Ok(beacons)
}

impl VerdantService {
    pub fn new(
        runtime: &tokio::runtime::Runtime,
        discovery: bool,
    ) -> Result<Self, keycast::errors::BeaconError> {
        let (ui_tx, ui_rx) = mpsc::unbounded_channel();
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let handle = runtime.handle().clone();
        // clone the command tx for the discovery thread to notify the service of additional servers
        // which will in turn notify the UI thread.
        let cmd_tx_clone = cmd_tx.clone();
        std::thread::spawn(move || {
            let mut discovered = Vec::new();
            let discovery_handle = if discovery {
                // try to find at least the first server, then launch background to get more servers
                let discoveries: Vec<Discovery> = handle.block_on(async move {
                    // here's where we discover servers
                    discover("verdant").await
                })?;
                println!("discovered: {:?}", discoveries);
                discovered.extend_from_slice(&discoveries);
                let known = discovered.clone();
                let discovery_handle = handle.spawn(async move {

                    /*while let Ok(mut beacons) = discover("verdant").await {
                        for beacon in beacons.into_iter() {
                            if !known.contains(&beacon) {
                                known.push(beacon.clone());
                                match cmd_tx_clone.send(VerdantCmd::ServerDiscovered(beacon)) {
                                    Ok(_) => continue,
                                    Err(e) => break,
                                }
                            }
                        }
                    }*/
                    // to be implemented
                });
                Some(discovery_handle)
            } else {
                None
            };
            let discovered_clients = discovered.clone();
            let service_handle = handle.spawn(async move {
                let mut clients = HashMap::new();
                for discovered_client in discovered_clients.into_iter() {
                    let url = discovered_client.urls().get(0).unwrap().to_string();
                    let client = APIClient::from_discovery(discovered_client).await.unwrap();
                    clients.insert(url, client);
                }
                verdant_service(cmd_rx, ui_tx, clients).await
            });
            Ok(Self {
                handle,
                discovery_handle,
                discovered,
                ui_rx,
                cmd_tx,
                service_handle,
            })
        })
        .join()
        .unwrap()
    }

    pub fn tx(&self) -> &UnboundedSender<VerdantCmd> {
        &self.cmd_tx
    }

    pub fn login(
        cmd_tx: &UnboundedSender<VerdantCmd>,
        url: impl Into<String>,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Result<(), mpsc::error::SendError<VerdantCmd>> {
        let request = VerdantCmd::Login(LoginRequest::new(url, username, password));
        cmd_tx.send(request)
    }

    pub fn discoveries(&self) -> &Vec<Discovery> {
        &self.discovered
    }

    pub fn try_recv(&mut self) -> Option<VerdantUiCmd> {
        match self.ui_rx.try_recv() {
            Ok(val) => Some(val),
            Err(_e) => None,
        }
    }
}

async fn verdant_service(
    mut cmd_rx: UnboundedReceiver<VerdantCmd>,
    ui_tx: UnboundedSender<VerdantUiCmd>,
    mut clients: HashMap<String, APIClient>,
) {
    while let Some(event) = cmd_rx.recv().await {
        match event {
            VerdantCmd::ServerDiscovered(discovery) => {
                let url = discovery.urls().get(0).unwrap().clone();
                let client = APIClient::from_discovery(discovery).await.unwrap();
                clients.insert(url, client);
            }
            VerdantCmd::Login(request) => {
                if let Some(client) = clients.get_mut(&request.url) {
                    let result = match client
                        .login(&request.username, &request.password)
                        .await {
                            Ok(result) => result,
                            Err(e) => {
                                eprintln!("login error: {}", e);
                                LoginResult::Unauthorized
                            },
                        };
                    println!("login result: {} {:?}", &request.username, result);
                    let cmd = VerdantUiCmd::LoginResult(result);
                    ui_tx.send(cmd).unwrap();

                    // now request token
                    if let Ok(response) = client.get_livekit_token().await {
                        ui_tx.send(VerdantUiCmd::LkToken(response)).unwrap();
                    }
                } else {
                    let result =
                        VerdantUiCmd::LoginResult(LoginResult::UnknownServer(request.url.clone()));
                    ui_tx.send(result).unwrap();
                }
            }
        }
    }
}

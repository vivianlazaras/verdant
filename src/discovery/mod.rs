use serde::{Serialize, Deserialize};
use std::net::{IpAddr, SocketAddr};
use tokio::{net::UdpSocket, task::JoinHandle, time::{interval, Duration}};
use mdns_sd::{ServiceDaemon, ServiceInfo};
use anyhow::{Result, anyhow};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Beacon {
    pub id: String,
    pub name: Option<String>,
    pub ip: IpAddr,
    pub port: u16,
    pub ttl: u32,
    /// base64 encoded string
    pub pubkey: String,
}

pub struct AdvertisementHandle {
    pub mdns: JoinHandle<()>,
    pub multicast: JoinHandle<()>,
}

impl Beacon {
    pub async fn advertise(&self, addr: IpAddr) -> Result<AdvertisementHandle> {
        // Validate multicast address
        let is_multicast = match addr {
            IpAddr::V4(ipv4) => ipv4.is_multicast(),
            IpAddr::V6(ipv6) => ipv6.is_multicast(),
        };
        if !is_multicast {
            return Err(anyhow!("Provided address {:?} is not a multicast address", addr));
        }

        // ---- Spawn mDNS Advertisement ----
        let name = self.name.clone().unwrap_or_else(|| "Unnamed WebKit Server".to_string());
        let instance_name = format!("{}._webkit._udp.local.", name);
        let ip_clone = self.ip;
        let port_clone = self.port;
        
        let mdns = tokio::spawn(async move {
            if let Ok(daemon) = ServiceDaemon::new() {
                let properties = [("protocol", "verdant"), ("version", "0.0.1")];
                let service_info = ServiceInfo::new(
                    "_webkit._udp.local.",
                    &instance_name,
                    &format!("{}.local.", name),
                    ip_clone,
                    port_clone,
                    &properties[..] // No TXT records — Beacon carries metadata
                );

                match service_info {
                    Ok(info) => {
                        if let Err(e) = daemon.register(info) {
                            eprintln!("[mDNS] Registration error: {:?}", e);
                        } else {
                            println!("[mDNS] Service registered as {}", instance_name);
                        }
                    }
                    Err(e) => eprintln!("[mDNS] Failed to build service info: {:?}", e),
                }

                // Keep daemon alive
                loop {
                    tokio::time::sleep(Duration::from_secs(60)).await;
                }
            } else {
                eprintln!("[mDNS] Failed to start service daemon");
            }
        });

        // ---- Spawn Multicast Beacon Sender ----
        let beacon = self.clone();
        let multicast = tokio::spawn(async move {
            let socket = match UdpSocket::bind(match addr {
                IpAddr::V4(_) => "0.0.0.0:0",
                IpAddr::V6(_) => "[::]:0",
            }).await {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("[Beacon] Failed to bind UDP socket: {:?}", e);
                    return;
                }
            };

            let group_addr = SocketAddr::new(addr, beacon.port);
            let mut interval = interval(Duration::from_secs(5));

            loop {
                interval.tick().await;

                if let Ok(payload) = serde_json::to_vec(&beacon) {
                    if let Err(e) = socket.send_to(&payload, group_addr).await {
                        eprintln!("[Beacon] Send error: {:?}", e);
                    }
                }
            }
        });

        Ok(AdvertisementHandle { mdns, multicast })
    }
}
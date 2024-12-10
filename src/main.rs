use pnet::datalink::{self, Channel, DataLinkSender};
use pnet::packet::ethernet::{EthernetPacket, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::udp::UdpPacket;
use pnet::packet::{MutablePacket, Packet};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use log::{debug, error, info, warn};
use clap::Parser;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Args {
    /// Network interface to listen on (e.g. en0, eth0)
    #[arg(short, long)]
    interface: String,

    /// Maximum packet size (MTU) in bytes
    #[arg(long, default_value = "1500")]
    max_packet_size: usize,

    /// Maximum number of concurrent connections
    #[arg(long, default_value = "1000")]
    max_connections: usize,

    /// Connection timeout in seconds
    #[arg(long, default_value = "30")]
    connection_timeout: u64,

    /// Rate limit window in seconds
    #[arg(long, default_value = "1")]
    rate_limit_window: u64,

    /// Maximum packets per rate limit window
    #[arg(long, default_value = "100")]
    max_packets_per_window: u32,

    /// Comma-separated list of whitelisted IPv4 addresses
    #[arg(short, long)]
    whitelist: String,
}

const SSDP_PORT: u16 = 1900;
const SSDP_MULTICAST: [u8; 4] = [239, 255, 255, 250];

#[derive(Debug)]
struct SecurityStats {
    packet_count: u32,
    last_rate_check: Instant,
}

#[derive(Debug)]
struct ConnectionState {
    dest_ip: Option<IpAddr>,    // Store first responder IP
    timestamp: Instant,
    packet_count: u32,
}

struct PacketFilter {
    connections: Arc<Mutex<HashMap<u16, ConnectionState>>>,
    security_stats: Arc<Mutex<SecurityStats>>,
    tx: Option<Box<dyn DataLinkSender>>,
    whitelist: Vec<Ipv4Addr>,   // Whitelisted Chromecast devices
    max_packet_size: usize,
    max_connections: usize,
    connection_timeout: u64,
    rate_limit_window: u64,
    max_packets_per_window: u32,
}

impl PacketFilter {
    fn new(whitelist: Vec<Ipv4Addr>, args: &Args) -> Self {
        PacketFilter {
            connections: Arc::new(Mutex::new(HashMap::new())),
            security_stats: Arc::new(Mutex::new(SecurityStats {
                packet_count: 0,
                last_rate_check: Instant::now(),
            })),
            tx: None,
            whitelist,
            max_packet_size: args.max_packet_size,
            max_connections: args.max_connections,
            connection_timeout: args.connection_timeout,
            rate_limit_window: args.rate_limit_window,
            max_packets_per_window: args.max_packets_per_window,
        }
    }


    fn check_rate_limit(&self) -> bool {
        let mut stats = self.security_stats.lock().unwrap();
        let now = Instant::now();
        
        if now.duration_since(stats.last_rate_check) >= Duration::from_secs(self.rate_limit_window) {
            stats.packet_count = 0;
            stats.last_rate_check = now;
        }
        
        stats.packet_count += 1;
        if stats.packet_count > self.max_packets_per_window {
            warn!("Rate limit exceeded: {} packets/sec", stats.packet_count);
            return false;
        }
        true
    }

    fn validate_packet(&self, packet: &Ipv4Packet) -> bool {
        // Basic sanity checks
        if packet.get_total_length() as usize > self.max_packet_size {
            warn!("Packet exceeds max size: {}", packet.get_total_length());
            return false;
        }

        if packet.get_version() != 4 {
            warn!("Invalid IP version: {}", packet.get_version());
            return false;
        }

        if packet.get_ttl() == 0 {
            warn!("Packet TTL is 0");
            return false;
        }

        true
    }

    fn process_outgoing_ssdp(&self, packet: &Ipv4Packet) -> bool {
        if let Some(udp) = UdpPacket::new(packet.payload()) {
            if udp.get_destination() == SSDP_PORT {
                let mut connections = self.connections.lock().unwrap();
                
                // Check connection limit
                if connections.len() >= self.max_connections {
                    warn!("Maximum connection limit reached");
                    return false;
                }
                
                connections.insert(
                    udp.get_source(),
                    ConnectionState {
                        dest_ip: None,
                        timestamp: Instant::now(),
                        packet_count: 0,
                    },
                );
                
                debug!("Tracked new SSDP discovery from port {}", udp.get_source());
                return true;
            }
        }
        false
    }

    fn should_allow_incoming(&self, packet: &Ipv4Packet) -> bool {
        if let Some(udp) = UdpPacket::new(packet.payload()) {
            let mut connections = self.connections.lock().unwrap();
            
            // Check if this is a response to a tracked SSDP discovery
            if let Some(state) = connections.get_mut(&udp.get_destination()) {
                // Validate source
                let source_ip = packet.get_source();
                if !self.whitelist.contains(&source_ip) {
                    warn!("Response from non-whitelisted IP: {}", source_ip);
                    return false;
                }

                // Check if we've seen this responder before
                if let Some(known_ip) = state.dest_ip {
                    if known_ip != IpAddr::V4(source_ip) {
                        warn!("Response from different IP than original responder");
                        return false;
                    }
                } else {
                    // First response, record the IP
                    state.dest_ip = Some(IpAddr::V4(source_ip));
                }

                // Update timestamp and count
                state.timestamp = Instant::now();
                state.packet_count += 1;
                
                debug!("Allowing response from {} to port {}", source_ip, udp.get_destination());
                return true;
            }
        }
        false
    }

    fn forward_packet(&mut self, ethernet: &EthernetPacket) -> Result<(), Box<dyn std::error::Error>> {
        let tx = self.tx.as_deref_mut().ok_or("Transmit channel not initialized")?;
        let mut new_buffer = vec![0u8; ethernet.packet().len()];
        let mut new_packet = MutableEthernetPacket::new(&mut new_buffer)
            .ok_or("Failed to create ethernet packet")?;
        
        // Copy and modify ethernet frame
        new_packet.clone_from(ethernet);
        
        // Forward the packet
        let _ = tx.send_to(new_packet.packet(), None)
            .ok_or("Failed to send packet")?;
        debug!("Forwarded packet of size {}", new_packet.packet().len());
        Ok(())
    }

    fn run(&mut self, interface_name: &str) -> Result<(), Box<dyn std::error::Error>> {
        let interface = datalink::interfaces()
            .into_iter()
            .find(|iface| iface.name == interface_name)
            .ok_or("Interface not found")?;

        // Create channel for packet transmission
        let (tx, mut rx) = match datalink::channel(&interface, Default::default()) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => return Err("Unhandled channel type".into()),
            Err(e) => return Err(Box::new(e)),
        };

        self.tx = Some(tx);

        // Start cleanup thread
        let connections_clone = Arc::clone(&self.connections);
        let timeout = self.connection_timeout;
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(Duration::from_secs(1));
                let mut connections = connections_clone.lock().unwrap();
                let now = Instant::now();
                let initial_count = connections.len();
                
                connections.retain(|_, state| {
                    now.duration_since(state.timestamp) < Duration::from_secs(timeout)
                });
                
                let removed = initial_count - connections.len();
                if removed > 0 {
                    info!("Cleaned up {} stale connections", removed);
                }
            }
        });

        info!("Started packet filter on interface {}", interface_name);

        loop {
            match rx.next() {
                Ok(packet) => {
                    if !self.check_rate_limit() {
                        continue;
                    }

                    if let Some(ethernet) = EthernetPacket::new(packet) {
                        if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) {
                            if !self.validate_packet(&ipv4) {
                                continue;
                            }

                            if ipv4.get_next_level_protocol() == IpNextHeaderProtocols::Udp {
                                // Handle outgoing SSDP
                                if ipv4.get_destination() == Ipv4Addr::from(SSDP_MULTICAST) {
                                    if self.process_outgoing_ssdp(&ipv4) {
                                        PacketFilter::forward_packet(self, &ethernet)?;
                                    }
                                }
                                // Handle incoming responses
                                else if self.should_allow_incoming(&ipv4) {
                                    PacketFilter::forward_packet(self, &ethernet)?;
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("Error receiving packet: {}", e);
                }
            }
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    
    let args = Args::parse();
    
    // Parse whitelist IPs
    let whitelist: Vec<Ipv4Addr> = args.whitelist
        .split(',')
        .map(|s| s.trim().parse())
        .collect::<Result<_, _>>()
        .map_err(|e| format!("Invalid whitelist IP address: {}", e))?;

    if whitelist.is_empty() {
        return Err("Whitelist cannot be empty".into());
    }
    
    let mut filter = PacketFilter::new(whitelist, &args);
    
    filter.run(&args.interface)?;
    Ok(())
}

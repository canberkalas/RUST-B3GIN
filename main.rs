use std::net::UdpSocket;
use std::thread;
use std::time::{Duration, Instant};

use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::{Packet, MutablePacket};
use pnet::transport::{transport_channel, TransportChannelType, TransportProtocol};
use pnet::util::MacAddr;

mod sensor_manager;
mod network_monitor;
mod security_rules;
mod logger;

fn main() {
    // Network interface MAC address
    let mac = MacAddr::new(0x00, 0x00, 0x00, 0x00, 0x00, 0x01); 

    // Create a UDP socket
    let (mut tx_udp, mut rx_udp) = transport_channel(
        2,
        TransportChannelType::Layer3(TransportProtocol::Udpv4),
        mac,
        Ipv4Addr::new(0, 0, 0, 0), // Listen to all IPs
    )
    .unwrap();

    // Load security rules
    let rules = security_rules::load_rules();

    // Start network traffic monitoring task
    let network_monitor_thread = thread::spawn(move || {
        loop {
            // Listen for incoming UDP packets
            match rx_udp.next_with_timeout(Duration::from_millis(100)) {
                Ok((packet, _)) => {
                    // UDP packet
                    let udp_packet = UdpPacket::new(packet).unwrap();
                    let src_ip = udp_packet.get_source();
                    let dst_port = udp_packet.get_destination();

                    // Check packet against security rules
                    if security_rules::check_rule(&src_ip, dst_port, udp_packet.get_next_header()) {
                        // Packet allowed
                        logger::log_event(&format!("UDP packet allowed: {}", src_ip));
                    } else {
                        // Packet blocked
                        logger::log_event(&format!("UDP packet blocked: {}", src_ip));
                    }
                }
                Err(_) => {}
            }
        }
    });

    // Start sensor data monitoring task
    //let sensor_thread = thread::spawn(move || {
    //    // Read and process sensor data (if needed)
    //});

    // Main thread manages sub-threads and keeps the program running
    network_monitor_thread.join().unwrap();
    //sensor_thread.join().unwrap();
}

use indicatif::ProgressBar;
use libc::{
    sockaddr, sockaddr_in, sockaddr_in6, socklen_t, AF_INET, AF_INET6, IPPROTO_IP, IPTOS_MINCOST,
    IP_TOS, IP_TTL,
};
use sha2::{Digest, Sha256};
use std::env;
use std::io::{self, Read, Write};
use std::mem;
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket,
};
use std::os::unix::io::AsRawFd;
use std::thread;
use std::time::Duration;

const TTL_VALUE_BIT_0: u8 = 254;
const TTL_VALUE_BIT_1: u8 = 253;
const PACKET_SIZE: usize = 1400;
const WINDOW_SIZE: usize = 1400;
const BURSTS:u8 = 4;

static mut PACKET_TRANSMISSION_RATE: u32 = 2000; // packets per second

#[derive(Debug, Clone)]
struct UdpPacket {
    header: UdpHeader,
    payload: UdpPayload,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct Ipv4Header {
    version_ihl: u8,
    tos: u8,
    total_length: u16,
    id: u16,
    flags_offset: u16,
    ttl: u8,
    protocol: u8,
    checksum: u16,
    src_addr: u32,
    dst_addr: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct UdpHeader {
    source_port: u16,
    destination_port: u16,
    length: u16,
    checksum: u16,
}

#[derive(Debug, Clone)]
struct UdpPayload {
    data: Vec<u8>,
}

struct TtlSENDChannel {
    socket: UdpSocket,
}

impl TtlSENDChannel {
    fn new_send() -> Self {
        // Create a new UDP socket
        let socket = UdpSocket::bind("0.0.0.0:0").expect("Failed to bind socket");

        // Create a new instance of TtlChannel with the socket and TTL values.
        TtlSENDChannel { socket }
    }

    fn send_bit(&mut self, bit: bool, destination: SocketAddr, hashing: &PasswordBasedHash) {
        let ttl_value = if bit {
            TTL_VALUE_BIT_1
        } else {
            TTL_VALUE_BIT_0
        };
        let result = unsafe {
            libc::setsockopt(
                self.socket.as_raw_fd(),
                IPPROTO_IP,
                IP_TTL,
                &ttl_value as *const _ as *const _,
                std::mem::size_of_val(&ttl_value) as u32,
            )
        };

        if result != 0 {
            panic!("Failed to set TTL");
        }

        let result_tos = unsafe {
            libc::setsockopt(
                self.socket.as_raw_fd(),
                IPPROTO_IP,
                IP_TOS,
                &IPTOS_MINCOST as *const _ as *const _,
                std::mem::size_of_val(&IPTOS_MINCOST) as u32,
            )
        };

        if result_tos != 0 {
            panic!("Failed to set TOS");
        }

        let mut packet = Vec::new();
        for byte in hashing.hash.as_bytes() {
            packet.push(*byte)
        }
        let padding = PACKET_SIZE - packet.len();
        packet.extend(vec![0; padding]);

        self.socket.send_to(&packet, destination).unwrap();
    }

    fn send_message(&mut self, data: Vec<u8>, mut destination: SocketAddr, burst: u8) {
        let progress_bar_len = data.len() / WINDOW_SIZE;

        let bar = ProgressBar::new(progress_bar_len as u64);
        let mut burst_count = 0;
        for c in data.chunks(WINDOW_SIZE) {
            self.socket.send_to(c, destination).unwrap();
            bar.inc(1 as u64);
            burst_count = burst_count + 1;
            destination = SocketAddr::new(destination.ip(), destination.port() + 1);
            if burst_count == burst{
                thread::sleep(Duration::from_millis(
                    (1000 / unsafe { PACKET_TRANSMISSION_RATE }).into(),
                ));
                burst_count = 0;
                destination = SocketAddr::new(destination.ip(), destination.port() - burst as u16);
            }
        }
    }
}

struct TtlRECVChannel {
    socket: i32,
    start_ttl: u8,
    hops: u8,
}

impl TtlRECVChannel {
    fn new_receive() -> Self {
        // Create a new raw socket
        let socket = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_UDP) };
        if socket < 0 {
            panic!("Failed to create raw socket");
        }

        let buffer_size = 1024 * 1024 * 50; // 50MB buffer size
        let buffer = buffer_size as libc::c_int;
        // Adding a buffer to the socket.
        unsafe {
            libc::setsockopt(
                socket,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &buffer as *const _ as *const libc::c_void,
                std::mem::size_of_val(&buffer) as u32,
            );
        }

        TtlRECVChannel {
            socket: socket,
            start_ttl: 100,
            hops: 254,
        }
    }

    fn checks(&mut self, udp_packet: UdpPacket, hashing: &PasswordBasedHash) -> bool {
        // Get the payload data
        let payload = &udp_packet.payload.data;
        let hash = hashing.hash.as_bytes();
        let mut passing = true;

        // Compare checks with payload
        for (index, &password) in hash.iter().enumerate() {
            if password != payload[index] {
                passing = false;
            }
        }

        if passing {
            return passing;
        }

        false
    }

    fn receive_bit(&mut self, ttl: u8, udp_packet: UdpPacket, hashing: &PasswordBasedHash) -> bool {
        let mut toggle: bool = true;
        let mut _dismiss: bool = false;
        if self.start_ttl == 100 {
            self.start_ttl = ttl;
            self.hops = TTL_VALUE_BIT_0 - ttl;
        }

        let pass = self.checks(udp_packet, hashing);

        match (self.start_ttl >= 100, ttl) {
            (true, ttl) if ttl == TTL_VALUE_BIT_0 - self.hops => {
                if pass {
                    toggle = true
                }
            }
            (true, ttl) if ttl == TTL_VALUE_BIT_1 - self.hops => {
                if pass {
                    toggle = false
                }
            }
            _ => _dismiss = true,
        }
        toggle
    }

    fn open_tcp_control_port(&mut self, port: u16) -> TcpListener {
        let receive_ip = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));
        let receive_socket = SocketAddr::new(receive_ip, port);
        TcpListener::bind(receive_socket).unwrap()
    }

    fn initialize_socket_address(&mut self) -> SocketAddr {
        let mut sockaddr_inv4: sockaddr_in = unsafe { std::mem::zeroed() };
        sockaddr_inv4.sin_family = AF_INET as u16;
        sockaddr_inv4.sin_port = 8080u16.to_be();
        sockaddr_inv4.sin_addr.s_addr = 0x7F000001; // 127.0.0.1 (IPv4 address)

        let src_addr: sockaddr = unsafe { std::mem::transmute(sockaddr_inv4) };

        sender_address_transform(&src_addr).unwrap()
    }

    fn receive_message(&mut self, initial_hashing: PasswordBasedHash) {
        let mut nb_packets: u64 = 0;
        let mut nb_packets_processed = 0;
        let mut nb_ports_to_use = 0;
        let mut stack: [Vec<Vec<u8>>; 4] = Default::default();
        let ipv4_header_len = std::mem::size_of::<Ipv4Header>();
        let udp_header_len = std::mem::size_of::<UdpHeader>();
        let packet_len = ipv4_header_len + udp_header_len + WINDOW_SIZE;
        //let total_header_len = ipv4_header_len + udp_header_len;
        let mut buffer = vec![0u8; packet_len];
        let mut ttl_initiator = true;
        let mut src_addr: sockaddr = unsafe { mem::zeroed() };
        let mut addrlen: socklen_t = mem::size_of_val(&src_addr) as socklen_t;
        let mut tcp_recv_stream: TcpStream;
        let mut previous_source_addr = self.initialize_socket_address();
        //let mut data = Vec::new();
        let mut bar: ProgressBar = ProgressBar::hidden();
        let mut original_destination_port = 0;
        loop {
            // Receive a packet
            let _bytes_received = unsafe {
                libc::recvfrom(
                    self.socket,
                    buffer.as_mut_ptr() as *mut libc::c_void,
                    buffer.len(),
                    0,
                    &mut src_addr as *mut _,
                    &mut addrlen,
                )
            };

            let src_addr = unsafe { &*(&src_addr as *const sockaddr) };
            let source_addr = sender_address_transform(src_addr).unwrap();

            if ttl_initiator || previous_source_addr.ip() == source_addr.ip() {
                let ttl = buffer[8];
                let udp_packet = parse_udp_packet(&buffer).unwrap();
                if ttl_initiator {
                    self.receive_bit(ttl, udp_packet.clone(), &initial_hashing);
                    original_destination_port = udp_packet.header.destination_port.to_be();
                    let tcp_incoming =
                        self.open_tcp_control_port(original_destination_port);
                    match tcp_incoming.accept() {
                        Ok((tcp_receive_stream, socket_addr)) => {
                            if socket_addr.ip() == source_addr.ip() {
                                tcp_recv_stream = tcp_receive_stream;
                                let mut tcp_nb_packets = [0; 9];
                                let bytes_read = tcp_recv_stream
                                    .read(&mut tcp_nb_packets)
                                    .expect("Failed to read from TCP stream");
                                if bytes_read != 9 {
                                    println!("ERROR: Did not read enough bytes from TCP stream");
                                    return;
                                }
                                nb_packets =
                                    u64::from_be_bytes(tcp_nb_packets[..8].try_into().unwrap());
                                nb_ports_to_use = u8::from_be_bytes(tcp_nb_packets[8..9].try_into().unwrap());
                                previous_source_addr = socket_addr;
                                tcp_recv_stream
                                    .shutdown(Shutdown::Both)
                                    .expect("Shutdown TCP sockets failed!");
                            }
                        }
                        Err(e) => {
                            println!("ERROR={}", e);
                        }
                    }
                    ttl_initiator = false;
                    bar = ProgressBar::new(nb_packets as u64);
                } else {
                    let udp_packet = parse_udp_packet(&buffer).unwrap();
                    self.handle_payload(udp_packet, original_destination_port, nb_ports_to_use, &mut stack);
                    nb_packets_processed = nb_packets_processed + 1;
                    bar.inc(1);
                
                    if nb_packets == nb_packets_processed {
                    break;
                    }
                    buffer = vec![0u8; packet_len]; //clear
                }
            }
        }
        let _ = io::stdout().write_all(&self.reassemble_packets(stack, nb_packets));
        let _ = io::stdout().flush();
    }

    fn handle_payload(&mut self, udp_packet:UdpPacket, original_destination_port: u16, nb_ports_total:u8, stack: &mut [Vec<Vec<u8>>;4]) {
        let max_port = original_destination_port + nb_ports_total as u16;
        let mut stack_index = 0;
        for port in original_destination_port..max_port{
            if udp_packet.header.destination_port.to_be() == port{
                stack[stack_index].push(udp_packet.payload.data.clone())
            }
            stack_index = stack_index + 1;
            if stack_index == 4{
                stack_index = 0;
            }
        }
    }

    fn reassemble_packets(&mut self, mut stack: [Vec<Vec<u8>>;4], nb_packets:u64) -> Vec<u8>{
        let mut reassembled_data = Vec::new();
        let mut stack_index = 0;
        for _packet in 0..nb_packets{
            if let Some(payload) = stack[stack_index].pop() {
                reassembled_data.extend(payload);
            }
            stack_index = stack_index + 1;
            if stack_index == 4{
                stack_index = 0;
            }
        }
        reassembled_data
    }
}

#[derive(Debug, Clone)]
struct PasswordBasedHash {
    hash: String,
}

impl PasswordBasedHash {
    fn new(password: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(password);
        let hash = array_to_string(hasher.finalize().into());
        PasswordBasedHash { hash }
    }
}

fn array_to_string(arr: [u8; 32]) -> String {
    String::from_utf8_lossy(&arr).into_owned()
}

fn parse_udp_packet(buffer: &[u8]) -> Result<UdpPacket, &'static str> {
    if buffer.len() < std::mem::size_of::<UdpHeader>() {
        return Err("Buffer too small to contain UDP packet");
    }

    let udp_header_offset = std::mem::size_of::<Ipv4Header>();
    let udp_header: UdpHeader =
        unsafe { *(buffer[udp_header_offset..].as_ptr() as *const UdpHeader) };

    let payload_offset = udp_header_offset + std::mem::size_of::<UdpHeader>();
    let payload_data: Vec<u8> = buffer[payload_offset..].to_vec();

    let payload = UdpPayload { data: payload_data };

    Ok(UdpPacket {
        header: udp_header,
        payload,
    })
}

fn tcp_control(channel: &mut TtlSENDChannel, data: Vec<u8>, destination: SocketAddr, nb_total_ports: u8) {
    let mut nb_packets = (data.len() / WINDOW_SIZE).to_be_bytes().to_vec();
    nb_packets.push(nb_total_ports.to_be());

    // Establish a tcp communication after a short 200ms sleep to let the server time to set up the socket.
    thread::sleep(Duration::from_millis(200));
    let stream = TcpStream::connect_timeout(&destination, Duration::from_millis(1000));
    match stream {
        Ok(mut tcp_control) => {
            let _ = tcp_control.write(&nb_packets);
            channel.send_message(data, destination, nb_total_ports);
        }
        Err(e) => {
            //couldn't connect to the TCP control port.
            println!("Error={}", e)
        }
    }
}

fn sender_address_transform(src_addr: &sockaddr) -> Option<SocketAddr> {
    unsafe {
        match (*src_addr).sa_family as i32 {
            AF_INET => {
                // Cast to sockaddr_in (IPv4)
                let src_addr_in = &*(src_addr as *const sockaddr as *const sockaddr_in);
                let ip = Ipv4Addr::from(u32::from_be(src_addr_in.sin_addr.s_addr));
                let port = u16::from_be(src_addr_in.sin_port);
                Some(SocketAddr::new(IpAddr::V4(ip), port))
            }
            AF_INET6 => {
                // Cast to sockaddr_in6 (IPv6)
                let src_addr_in6 = &*(src_addr as *const sockaddr as *const sockaddr_in6);
                let ip = Ipv6Addr::from(src_addr_in6.sin6_addr.s6_addr);
                let port = u16::from_be(src_addr_in6.sin6_port);
                Some(SocketAddr::new(IpAddr::V6(ip), port))
            }
            _ => {
                // Unsupported address family
                None
            }
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 3 {
        println!("Usage: ttl_channel [send*|receive] [destination*] [password] [Packets Bursts[40] Per Seconds*[default=12]] ");
        return;
    }

    let action = &args[1];
    if action == "send" {
        let hashing = PasswordBasedHash::new(&args[3].as_bytes());
        if args.len() == 5 {
            unsafe { PACKET_TRANSMISSION_RATE = args[4].parse().unwrap() };
        }
        let mut data = Vec::new();
        io::stdin()
            .read_to_end(&mut data)
            .expect("Failed to read from stdin");
        let destination_to = &args[2];
        let destination: SocketAddr = destination_to.parse().expect("Invalid destination address");
        let mut channel = TtlSENDChannel::new_send();
        channel.send_bit(false, destination, &hashing); // Adjust the receiving end's TTL.

        tcp_control(&mut channel, data, destination, BURSTS);
    } else if action == "receive" {
        let hashing = PasswordBasedHash::new(&args[2].as_bytes());
        let mut channel = TtlRECVChannel::new_receive();
        channel.receive_message(hashing);
    } else {
        println!("Invalid action. Please use 'send' or 'receive'.");
    }
}

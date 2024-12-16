use libc::{IPPROTO_IP, IP_TTL, IP_TOS, IPTOS_MINCOST};
use std::env;
use std::io::{self, Write, Read};
use std::mem;
use std::net::{SocketAddr, UdpSocket};
use std::os::unix::io::AsRawFd;
use std::thread;
use std::time::Duration;
use sha2::{Sha256, Digest};

const TTL_VALUE_BIT_0: u8 = 254;
const TTL_VALUE_BIT_1: u8 = 253;
const PACKET_SIZE: usize = 100;
static mut PACKET_TRANSMISSION_RATE: u32 = 96; // packets per second ( 1 packet/second/hop = normal): i32 = 96;


const PASSWORDS: [&str; 165] = [
    "8aJ#dF7pP!wQ", "XmL9zC&3sT2r", "w4kH#7Gp!vQn", "Yz6hP&1TbOeX", "z8P0D!mR7dJw",
    "QmL9tU2ZpV!r", "J7y@xDq6eZP0", "Lz$6QsP3fT1y", "p8LZx!w2VmFQ", "BvA!xT9yQw8f",
    "Jz!2W9tF7mNp", "uP3fQjX2wR#d", "Z1Y@oV7mFwzX", "B!9hM4LqQJ8n", "jN2pUo8M@3yX",
    "H4mO7B%8qA9X", "tWv0#pQ9zJk2", "Fj7z8Kx1pA6n", "WvT1h9bZ6eJm", "4qYj7U9XoK2L",
    "Yh8rD!2V3Jp9", "p9Rz7X0aT6vQ", "H!9d3XpV2t0m", "oV5sT2m6rXj0", "B8zP7Q!vJ2k0",
    "8uVqR#Fz4d0k", "Jv8z3WhR0o2p", "hKz7!tL5WQp0", "uP6j2C7wQZm3", "V!9h0J7YqW1n",
    "9fFm!X3qL2vR", "Q4h1A9tW!jNx", "pLz8Xk7D6oY2", "Jw!2F9mQ1PzX", "d8X4J0sT2m6K",
    "nP0w9T#k7LmV", "H5mX!v8QjL3N", "7uFz1Q0Lw8P2", "j0P!V7b6cXtF", "M4p0Yz2nX1sQ",
    "hGz8d6R9t3p0", "R8XoQw2L7jK!", "9pN2YhL3mQ0V", "Jwz8hT3f1XQp", "a1X!mZ9B0PvF",
    "Yk2QzR3pW!0X", "j0P6nF7wXtY1", "T8r9qZL4mX2f", "HqJ7Bz4v3P1t", "G8rXf2w9V!2P",
    "3vW1hF5zQ!gM", "p2L8bJY4rXw9", "Qw9z0bY4Tj1m", "N7Xz5FpJ9w1V", "F9uT0w7dLm3P",
    "t9L8xV!2oQj7", "z0J9h3Fq5p8W", "k8X9Z6tRj1sQ", "G7hP0m2yF!wT", "T6Xz3r7mJ1P0",
    "9bR2jL4W!t6k", "h6XqP8w7dYt9", "V9mQ!L5pJ1X0", "F4z8Wj2K0mQX", "w7H3vX2sT9P0",
    "R9Z2qL1mJ8vT", "J3xL9t0f7FqZ", "T!2W9rB7p6nX", "X4z0N3jLp5YV", "k1hQ7XfP0W9t",
    "3pV0tX7LwY2z", "Wz5P8k9F1b0J", "M2vXq9L7wT3f", "F8W1L0t7hXj2", "zP6Qm1yJ9XvT",
    "1p6J7f2T8QwL", "m3Yz9F8XqL4t", "X7W2z3Qp9hT1", "T8yP0wQ2jK7n", "f1R8z2Xj3P0v",
    "L5QpJ7vT9X1Z", "W3t2X9zF0mQk", "pL7X9j0F2QwV", "B8v4W0yF1QzT", "R9X2nJ3m4T0z",
    "8yK1fX9mQ0bL", "t2Q9wJ5pX0L7", "W3bF9L0v7Xq8", "jL4X7p9T6Fq0", "B5X8mJ1T2q3f",
    "h1Fz7QX4p2J0", "N8p4W1Xz7Qm0", "8Qm9wR1L7Y2v", "H0pF9Q7T8L4X", "kL6t0w9X1zY7",
    "7fX8J2Qp1wV0", "Q9b2X3zJ7P0m", "Y3X5b8P1J7m0", "4pL9X8QJ0w6r", "L7XqF1T9m0V2",
    "zP0V7Q9hJ3wX", "F8J6mQp0X2T9", "T7w1X9bQ2J0V", "hL0t9wX4P1F7", "V2Qm3L9J0yT1",
    "J0W1P9Qx7Y6z", "qP8J6X1w0mT7", "9T2L0bJ4X1Yz", "X5L7pT2J3w0Q", "8V9R0X2F6yQj",
    "J3z9F7W8b0T1", "6Xz7Y8q2pQ1L", "b4J0X9v6wP2R", "5pT8X3J7L9z0", "R6w0F9J1pQ2X",
    "T9mL8Y0pQ5zX", "0X9Q7bJ1L6pT", "1J8X4F3L2zP9", "m8P0X2v7T9Q1", "X4t9w7J0b6V1",
    "J0F3X1pL2wT8", "8V2Q7Y1X9T0m", "B0P9tF1X7J8Y", "W2X9Q0b4Jm7P", "L9Z1Q2X7T0mP",
    "X8J7w0L1Q9vT", "0Q2X7b6L9jP3", "z1X5V9P4F0Q2", "0T7X9pF8Q1J6", "7Q8X9p3T0J1v",
    "T9b1X7Q0L2vW", "F8t1P0X9J3L2", "Q0L2F7T1P6wJ", "7mL8Q9p1T2wX", "9J4t7F0X3Qm1",
    "6X2L0T8P9wQ3", "1X9J3T0bQ6YF", "Q5L2X7t8J9m0", "9wF2Q4J7X1bT", "8T1F7Q2X3vL0",
    "X2L0T6P7Q9J1", "9T8X5L0pJ1m3", "J0X9pF7L2wT3", "P7L0Q9X1mT8b", "X2mQ9L7T1F3p",
    "V0X9J2F7T1bP", "3J0X9L1T4F2v", "2m7F9T1Q0P8X", "9J1T3L7Q8pF0", "P1J2X6L9T7v0",
    "0mX1P7Q2F9bL", "T1pQ8J7F9X3v", "5bJ3X8T1Q7L2", "7P1T0J9X2F6L", "Q2J9L4X7F0T1",
    "8X2L9Q1F7J0P", "Q3T7L1F9X0P2", "9bX0L6F7J8m1", "F2T0X1P9L3J7", "Q9mX1L0P7F8T",
    "1P9J7X2F0L8Q", "T7F2X9bL0J1Q", "L9X0F7T2P8J1", "J0T8F7X2Q1L9", "P1F9X0L8J7T2"
];


#[derive(Debug, Clone, Copy)]
struct UdpPacket {
    ipv4_header: Ipv4Header,
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

#[derive(Debug, Clone, Copy)]
struct UdpPayload {
    data: [u8; PACKET_SIZE],
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

    fn send_bit(&mut self, bit: bool, destination: SocketAddr, hashing:&PasswordBasedHash) {
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

        if result != 0{
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
        
        if result_tos != 0{
            panic!("Failed to set TOS");
        }

        let mut packet = Vec::new();
        for byte in hashing.hash.as_bytes(){
            packet.push(*byte)
        }
        let padding = PACKET_SIZE - packet.len();
        packet.extend(vec![0; padding]);

        self.socket.send_to(&packet, destination).unwrap();
    }

    fn send_message(&mut self, message: &str, destination: SocketAddr) {
        let mut password_index = 0;
        for c in message.chars() {
            let bits = to_bits(c as u8);
            for bit in bits.iter() {
                let hashing = PasswordBasedHash::new(PASSWORDS[password_index].as_bytes());
                self.send_bit(*bit, destination, &hashing);
                //if *bit == true {
                //print!("1");
                //} else {
                //print!("0");
                //}
                thread::sleep(Duration::from_millis(
                    (2000 / unsafe {PACKET_TRANSMISSION_RATE}).into(),
                ));
                if password_index == PASSWORDS.len() -1{
                    password_index = 0;
                } else {
                    password_index = password_index + 1;
                }
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

        // Set socket options to include the IP header
        let opt: libc::c_int = 1;
        unsafe {
            libc::setsockopt(
                socket,
                libc::IPPROTO_IP,
                libc::IP_HDRINCL,
                &opt as *const _ as *const libc::c_void,
                mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }

        let buffer_size = 1024 * 1024 * 10; // 10MB buffer size
        let buffer = buffer_size as libc::c_int;

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

    fn checks(&mut self, udp_packet: UdpPacket, hashing:&PasswordBasedHash) -> bool {
        // Get the payload data
        let payload = &udp_packet.payload.data;
        let hash = hashing.hash.as_bytes();
        let mut passing = true;

        //println!("{}", String::from_utf8(hash.to_vec()).unwrap());
        //println!("{}", String::from_utf8(payload.to_vec()).unwrap());
        //println!("");
            
        // Compare checks with payload
        for (index, &password) in hash.iter().enumerate() {
            if password != payload[index] {
                //println!("FAILED--CHECKS at index {}", index);
                passing = false;
            }
        }
            
        if passing{
        //println!("IP CHECKS PASSED");
            return passing
        }

        false
    }

    fn receive_bit(&mut self, udp_packet: UdpPacket, hashing:&PasswordBasedHash) -> bool {
        //print!("RECEIVING bit-->");
        let mut toggle: bool = true;
        let mut _dismiss: bool = false;
        let ttl = udp_packet.ipv4_header.ttl;
        if self.start_ttl == 100 {
            self.start_ttl = udp_packet.ipv4_header.ttl;
            self.hops = TTL_VALUE_BIT_0 - udp_packet.ipv4_header.ttl; //254 - 241 = 13 hops ahead.
        }

        //println!("HOPS-->{}", self.hops);
        //println!("TTL-->{}", ttl);

        let pass = self.checks(udp_packet, hashing);

        //println!("{}", self.hops);
        match (self.start_ttl >= 100, ttl) {
            (true, ttl) if ttl == TTL_VALUE_BIT_0 - self.hops => {
                //print!("0");
                //io::stdout().flush().expect("Failed to flush stdout");
                if pass {
                    //println!("TOGGLED-TRUE");
                    toggle = true
                }
            }
            (true, ttl) if ttl == TTL_VALUE_BIT_1 - self.hops => {
                //print!("1");
                //io::stdout().flush().expect("Failed to flush stdout");
                if pass {
                    //println!("TOGGLED-FALSE");
                    toggle = false
                }
            }
            _ => {
                // Handle other cases if needed
                _dismiss = true // or whatever default behavior you want
            }
        }
        toggle
    }

    fn receive_message(&mut self, initial_hashing:PasswordBasedHash) -> String {
        let mut message = String::new();
        println!("RECEIVING-MESSAGE-->");
        // Buffer to hold the incoming packet
        let mut buffer = vec![0u8; 65535]; // Maximum size for an IP packet
        let mut bits = [false; 8];
        let mut bit_count = 0;
        let mut ttl_initiator = true;
        let mut password_index = 0;
        //let mut first: bool = false;
        loop {
            // Receive a packet
            let bytes_received = unsafe {
                libc::recvfrom(
                    self.socket,
                    buffer.as_mut_ptr() as *mut libc::c_void,
                    buffer.len(),
                    0,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };

            if bytes_received < 0 {
                continue;
            }

            // Parse the IP header
            let udp_packet = parse_udp_packet(&buffer).unwrap();

            if ttl_initiator {
                self.receive_bit(udp_packet.clone(), &initial_hashing);
                println!("-->Received Password!");
                ttl_initiator = false;
                //first = true;
            } else {
                //println!("BITCOUNT={}", bit_count);
                //println!("TTL-->{}", ip_header.ttl);
                let hashing = PasswordBasedHash::new(PASSWORDS[password_index].as_bytes());
                bits[bit_count] = self.receive_bit(udp_packet.clone(), &hashing);

                bit_count = bit_count + 1;

                if bit_count == 8 {
                    //println!("");
                    let mut bitstream = String::new();
                    for bit in bits {
                        if !bit {
                            //print!("1");
                            //io::stdout().flush().expect("Failed to flush stdout");
                            bitstream.push('1');
                        } else {
                            //print!("0");
                            //io::stdout().flush().expect("Failed to flush stdout");
                            bitstream.push('0');
                        }
                    }
                    //print!("-->");

                    let decimal_value = i32::from_str_radix(&bitstream, 2).unwrap();
                    //let byte = to_bytes(bits);
                    //println!("decimal={}", decimal_value);
                    let c = match char::from_u32(decimal_value as u32) {
                        Some(c) => c,
                        None => '?',
                    };
                    message.push(c);
                    print!("{}", c);
                    io::stdout().flush().expect("Failed to flush stdout");
                    bit_count = 0;
                }
                if password_index == PASSWORDS.len() -1{
                    password_index = 0;
                } else {
                    password_index = password_index + 1;
                }
            }
        }
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

fn to_bits(byte: u8) -> [bool; 8] {
    let mut bits = [false; 8];
    for i in 0..8 {
        bits[7 - i] = (byte & (1 << i)) != 0; // Set bits in reverse order (big-endian)
    }
    bits
}

fn to_bytes(bits: [bool; 8]) -> u8 {
    let mut byte = 0;
    for (i, bit) in bits.iter().enumerate() {
        if *bit {
            byte |= 1 << (7 - i); // Set bits in reverse order (big-endian)
        }
    }
    byte
}

fn parse_udp_packet(buffer: &[u8]) -> Result<UdpPacket, &'static str> {
    if buffer.len() < std::mem::size_of::<Ipv4Header>() + std::mem::size_of::<UdpHeader>() {
        return Err("Buffer too small to contain UDP packet");
    }

    let ipv4_header: Ipv4Header = unsafe { *(buffer.as_ptr() as *const Ipv4Header) };
    let udp_header_offset = std::mem::size_of::<Ipv4Header>();
    let udp_header: UdpHeader = unsafe {
        *(buffer[udp_header_offset..].as_ptr() as *const UdpHeader)
    };

    let payload_offset = udp_header_offset + std::mem::size_of::<UdpHeader>();
    let payload_data: [u8; PACKET_SIZE] = buffer[payload_offset..payload_offset+PACKET_SIZE]
        .try_into()
        .map_err(|_| "Payload size mismatch")?;

    let payload = UdpPayload { data: payload_data };

    Ok(UdpPacket {
        ipv4_header,
        header:udp_header,
        payload,
    })
}


fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 3 {
        println!("Usage: ttl_channel [send*|receive] [destination*] [password] [Packets Per Seconds*[default=96]] ");
        return;
    }

    
    let action = &args[1];
    if action == "send" {
        let hashing = PasswordBasedHash::new(&args[3].as_bytes());
        if args.len() == 5{
            unsafe {PACKET_TRANSMISSION_RATE = args[4].parse().unwrap()};
        }
        let mut message = String::new();
        io::stdin().read_to_string(&mut message).expect("Failed to read from stdin");
        let destination_to = &args[2];
        let destination: SocketAddr = destination_to.parse().expect("Invalid destination address");
        let mut channel = TtlSENDChannel::new_send();
        channel.send_bit(false, destination, &hashing); // Adjust the receiving end's TTL.
        channel.send_message(&message, destination);
    } else if action == "receive" {
        let hashing = PasswordBasedHash::new(&args[2].as_bytes());
        let mut channel = TtlRECVChannel::new_receive();
        channel.receive_message(hashing);
    } else {
        println!("Invalid action. Please use 'send' or 'receive'.");
    }
}

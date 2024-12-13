use std::net::{SocketAddr, UdpSocket};
use std::thread;
use std::time::Duration;
use std::env;
use std::os::unix::io::AsRawFd;
use libc::{IPPROTO_IP, IP_TTL};
use std::mem;
use std::io::{self, Write};

const TTL_VALUE_BIT_0: u8 = 254;
const TTL_VALUE_BIT_1: u8 = 253;
const PACKET_SIZE: usize = 40; // Emulate traceroute
const PACKET_TRANSMISSION_RATE: u32 = 1; // packets per second ( 1 packet/second/hop = normal)

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

struct TtlSENDChannel {
    socket: UdpSocket,
}

impl TtlSENDChannel {
    fn new_send() -> Self {
        // Create a new UDP socket
        let socket = UdpSocket::bind("0.0.0.0:0").expect("Failed to bind socket");

        // Create a new instance of TtlChannel with the socket and TTL values.
        TtlSENDChannel { 
            socket, 
        }
    }

    fn send_bit(&mut self, bit: bool, destination: SocketAddr) {
        let ttl_value = if bit { TTL_VALUE_BIT_1 } else { TTL_VALUE_BIT_0 };
        let result = unsafe {
            libc::setsockopt(self.socket.as_raw_fd(), IPPROTO_IP, IP_TTL, &ttl_value as *const _ as *const _, std::mem::size_of_val(&ttl_value) as u32)
        };
        if result != 0 {
            panic!("Failed to set TTL");
        }
        let packet = vec![0; PACKET_SIZE];
        self.socket.send_to(&packet, destination).unwrap();
    }

    fn send_message(&mut self, message: &str, destination: SocketAddr) {
        for c in message.chars() {
            let bits = to_bits(c as u8);
            for bit in bits.iter() {
                self.send_bit(*bit, destination);
                if *bit == true{
                    print!("1");
                } else {
                    print!("0");
                }
                thread::sleep(Duration::from_millis((1000 / PACKET_TRANSMISSION_RATE).into()));
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
            libc::setsockopt(socket, libc::IPPROTO_IP, libc::IP_HDRINCL, &opt as *const _ as *const libc::c_void, mem::size_of::<libc::c_int>() as libc::socklen_t);
        }

        TtlRECVChannel {
            socket: socket,
            start_ttl: 100,
            hops: 254
        }
    }

    fn receive_bit(&mut self, ttl: u8) -> bool {
        //print!("RECEIVING bit-->");
        let mut toggle:bool = true;
        let mut _dismiss:bool = false;
        if self.start_ttl == 100 {
            self.start_ttl = ttl;
            self.hops = TTL_VALUE_BIT_0 - ttl; //254 - 241 = 13 hops ahead.
        }

        //println!("{}", self.hops);
        match (self.start_ttl >= 100, ttl) {
            (true, ttl) if ttl == TTL_VALUE_BIT_0 - self.hops => {
                //print!("0");
                //io::stdout().flush().expect("Failed to flush stdout");
                toggle = true
            },
            (true, ttl) if ttl == TTL_VALUE_BIT_1 - self.hops => {
                //print!("1");
                //io::stdout().flush().expect("Failed to flush stdout");
                toggle = false
            },
            _ => {
                // Handle other cases if needed
                _dismiss = true // or whatever default behavior you want
            }
        }
        toggle
        
    }

    fn receive_message(&mut self) -> String {
        let mut message = String::new();
        println!("RECEIVING-MESSAGE-->");
        // Buffer to hold the incoming packet
        let mut buffer = vec![0u8; 65535]; // Maximum size for an IP packet
        let mut bits = [false; 8];
        let mut bit_count = 0;
        let mut ttl_initiator = true;
        let mut first:bool = false;
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
                continue
            }

            // Parse the IP header
            let ip_header: &Ipv4Header = unsafe { &*(buffer.as_ptr() as *const Ipv4Header) };

            if ttl_initiator{
                self.receive_bit(ip_header.ttl);
                ttl_initiator = false;
                first = true;
            } else {
                if first{
                    first = false
                } else {
                    //println!("BITCOUNT={}", bit_count);
                    //println!("TTL-->{}", ip_header.ttl);
                    bits[bit_count] = self.receive_bit(ip_header.ttl);

                    bit_count = bit_count + 1;

                    if bit_count == 8{
                        println!("");
                        let mut bitstream = String::new();
                        for bit in bits{
                            if !bit{
                                //print!("1");
                                //io::stdout().flush().expect("Failed to flush stdout");
                                bitstream.push('1');
                            } else {
                                //print!("0");
                                //io::stdout().flush().expect("Failed to flush stdout");
                                bitstream.push('0');
                            }
                        }
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
                }
            }
        }
    }
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


fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!("Usage: ttl_channel [send*|receive] [destination*] [message*]");
        return;
    }

    let action = &args[1];
    if action == "send" {
        let destination_to = &args[2];
        let destination: SocketAddr = destination_to.parse().expect("Invalid destination address");
        let mut channel = TtlSENDChannel::new_send();
        channel.send_bit(false, destination); // Adjust the receiving end's TTL.
        let message = &args[3];
        channel.send_message(message, destination);
    } else if action == "receive" {
        let mut channel = TtlRECVChannel::new_receive();
        channel.receive_message();
    } else {
        println!("Invalid action. Please use 'send' or 'receive'.");
    }
}
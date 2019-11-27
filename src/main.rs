use endianness::{read_u16, ByteOrder};
use std::io;

const IPV4_PROTO: u16 = 0x800;
const TCP_PROTO: u8 = 0x06;
type EthernetFlags = u16;
type EthernetProto = u16;

fn main() -> io::Result<()> {
    let iface = tun_tap::Iface::new("tun0", tun_tap::Mode::Tun)?;
    let mut buf = [0u8; 1504];
    loop {
        let nbytes = iface.recv(&mut buf[..])?;
        let (_eth_flags, eth_proto) = parse_ethernet_headers(&mut buf);
        if eth_proto != IPV4_PROTO {
            // not ipv4, skip
            continue;
        }

        match etherparse::Ipv4HeaderSlice::from_slice(&buf[4..nbytes]) {
            Ok(p) => {
                let src = p.source_addr();
                let dst = p.destination_addr();
                let proto = p.protocol();
                let payload_len = p.payload_len();
                if proto != TCP_PROTO {
                    // not tcp, skip
                    continue;
                }

                match etherparse::TcpHeaderSlice::from_slice(&buf[4 + p.slice().len()..]) {
                    Ok(tcp) => {
                        eprintln!(
                            "{} -> {} {} bytes of tcp to port {}",
                            src,
                            dst,
                            payload_len,
                            tcp.destination_port()
                        );
                    }
                    Err(e) => {
                        eprintln!("Parse error, ignoring tcp package: {:?}", e);
                    }
                }
            }
            Err(e) => {
                eprintln!("Parse error, ipv4 ignoring package: {:?}", e);
            }
        }
    }
}

fn parse_ethernet_headers(buf: &mut [u8]) -> (EthernetFlags, EthernetProto) {
    let flags = read_u16(&buf[0..2], ByteOrder::BigEndian).unwrap();
    let proto = read_u16(&buf[2..4], ByteOrder::BigEndian).unwrap();
    (flags, proto)
}

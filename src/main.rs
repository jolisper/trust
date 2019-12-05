use endianness::{read_u16, ByteOrder};
use std::collections::HashMap;
use std::io;
use std::net::Ipv4Addr;

// Protocol numbers https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
const IPV4_PROTO: u16 = 0x800;
const TCP_PROTO: u8 = 0x06;

type EthernetFlags = u16;
type EthernetProto = u16;

mod tcp;

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
struct Connection {
    src: (Ipv4Addr, u16),
    dst: (Ipv4Addr, u16),
}

fn main() -> io::Result<()> {
    let mut connections: HashMap<Connection, tcp::State> = Default::default();
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
            Ok(iph) => {
                let src = iph.source_addr();
                let dst = iph.destination_addr();
                if iph.protocol() != TCP_PROTO {
                    // not tcp, skip
                    continue;
                }

                match etherparse::TcpHeaderSlice::from_slice(&buf[4 + iph.slice().len()..nbytes]) {
                    Ok(tcph) => {
                        let datai = 4 + iph.slice().len() + tcph.slice().len();
                        connections
                            .entry(Connection {
                                src: (src, tcph.source_port()),
                                dst: (dst, tcph.destination_port()),
                            })
                            .or_default()
                            .on_packet(iph, tcph, &buf[datai..nbytes]);
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

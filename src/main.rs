use std::collections::HashMap;
use std::io;
use std::net::Ipv4Addr;

// Protocol numbers https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
const TCP_PROTO: u8 = 0x06;

mod tcp;

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
struct Peers {
    src: (Ipv4Addr, u16),
    dst: (Ipv4Addr, u16),
}

fn main() -> io::Result<()> {
    let mut connections: HashMap<Peers, tcp::Connection> = Default::default();
    let mut iface = tun_tap::Iface::without_packet_info("tun0", tun_tap::Mode::Tun)?;
    let mut buf = [0u8; 1504];
    loop {
        let nbytes = iface.recv(&mut buf[..])?;
        match etherparse::Ipv4HeaderSlice::from_slice(&buf[..nbytes]) {
            Ok(iph) => {
                let src = iph.source_addr();
                let dst = iph.destination_addr();
                if iph.protocol() != TCP_PROTO {
                    // not tcp, skip
                    continue;
                }

                match etherparse::TcpHeaderSlice::from_slice(&buf[iph.slice().len()..nbytes]) {
                    Ok(tcph) => {
                        use std::collections::hash_map::Entry;
                        let datai = iph.slice().len() + tcph.slice().len();
                        match connections.entry(Peers {
                            src: (src, tcph.source_port()),
                            dst: (dst, tcph.destination_port()),
                        }) {
                            Entry::Occupied(mut e) => {
                                let c = e.get_mut();
                                c.on_packet(&mut iface, iph, tcph, &buf[datai..nbytes])?;
                            }
                            Entry::Vacant(e) => {
                                if let Some(conn) = tcp::Connection::accept(
                                    &mut iface,
                                    iph,
                                    tcph,
                                    &buf[datai..nbytes],
                                )? {
                                    e.insert(conn);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Parse error, ignoring tcp package: {:?}", e);
                    }
                }
            }
            Err(e) => {
                //eprintln!("Parse error, ipv4 ignoring package: {:?}", e);
            }
        }
    }
}

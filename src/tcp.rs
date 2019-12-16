// https://tools.ietf.org/html/rfc793#section-3.2 [Page 22]
enum State {
    // Closed,
    // Listen,
    SynRcvd,
    Estab,
}

pub struct Connection {
    state: State,
    send: SendSequenceSpace,
    recv: ReceiveSequenceSpace,
    ip: etherparse::Ipv4Header,
}

/// States of the Send Sequence Space (RFC 793 S3.2 F4)
///
/// ```
///           1         2          3          4
///       ----------|----------|----------|----------
///              SND.UNA    SND.NXT    SND.UNA
///                                   +SND.WND
///
/// 1 - old sequence numbers which have been acknowledged
/// 2 - sequence numbers of unacknowledged data
/// 3 - sequence numbers allowed for new data transmission
/// 4 - future sequence numbers which are not yet allowed
/// ```
struct SendSequenceSpace {
    /// send unacknowledged
    una: u32,
    /// send next
    nxt: u32,
    /// send window
    wnd: u16,
    /// send urgent pointer
    up: bool,
    /// segment sequence number used for last window update
    wl1: u16,
    /// segment acknowledgment number used for last window update
    wl2: u16,
    /// initial send sequence number
    iss: u32,
}

/// States of the Receive Sequence Space (RFC 793 S3.2 F5)
///
///```
///               1          2          3
///           ----------|----------|----------
///                  RCV.NXT    RCV.NXT
///                            +RCV.WND
///
/// 1 - old sequence numbers which have been acknowledged
/// 2 - sequence numbers allowed for new reception
/// 3 - future sequence numbers which are not yet allowed
/// ```
struct ReceiveSequenceSpace {
    /// receive next
    nxt: u32,
    /// receive window
    wnd: u16,
    /// receive urgent pointer
    up: bool,
    /// initial receive sequence number
    irs: u32,
}

const TCP_TTL: u8 = 64;

impl Connection {
    pub fn accept<'a>(
        iface: &mut tun_tap::Iface,
        iph: etherparse::Ipv4HeaderSlice<'a>,
        tcph: etherparse::TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> std::io::Result<Option<Self>> {
        let mut buf = [0u8; 1500];

        if !tcph.syn() {
            // only expected syn packet
        }

        let iss = 0;
        let mut conn = Connection {
            state: State::SynRcvd,
            send: SendSequenceSpace {
                iss,
                una: iss,
                nxt: iss + 1,
                wnd: 10,
                wl1: 0,
                wl2: 0,
                up: false,
            },
            recv: ReceiveSequenceSpace {
                irs: tcph.sequence_number(),
                nxt: tcph.sequence_number() + 1,
                wnd: tcph.window_size(),
                up: false,
            },
            ip: etherparse::Ipv4Header::new(
                0,
                TCP_TTL,
                etherparse::IpTrafficClass::Tcp,
                [
                    iph.destination()[0],
                    iph.destination()[1],
                    iph.destination()[2],
                    iph.destination()[3],
                ],
                [
                    iph.source()[0],
                    iph.source()[1],
                    iph.source()[2],
                    iph.source()[3],
                ],
            ),
        };

        // start to establishing a connection
        let mut syn_ack = etherparse::TcpHeader::new(
            tcph.destination_port(),
            tcph.source_port(),
            conn.send.iss,
            conn.send.wnd,
        );
        syn_ack.acknowledgment_number = conn.recv.nxt;
        syn_ack.syn = true;
        syn_ack.ack = true;
        syn_ack.checksum = syn_ack
            .calc_checksum_ipv4(&conn.ip, &[])
            .expect("failed to compute checksum");
        conn.ip.set_payload_len((syn_ack.header_len() + 0) as usize);

        let unwritten = {
            let mut unwritten = &mut buf[..];
            conn.ip
                .write(&mut unwritten)
                .expect("failed writing ip header to buffer");
            syn_ack
                .write(&mut unwritten)
                .expect("failed writing tcp header to buffer");
            unwritten.len()
        };
        iface.send(&buf[..unwritten])?;
        Ok(Some(conn))
    }

    pub fn on_packet<'a>(
        &mut self,
        iface: &mut tun_tap::Iface,
        iph: etherparse::Ipv4HeaderSlice<'a>,
        tcph: etherparse::TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> std::io::Result<()> {
        // A new acknowledgment (called an "acceptable ack"), is one for which
        // the inequality below holds:
        //
        // SND.UNA < SEG.ACK =< SND.NXT
        let ackn = tcph.acknowledgment_number();
        if self.send.una < ackn {
            // check is violated iff SND.NXT is between SND.UNA and SEG.ACK
            if self.send.nxt >= self.send.una && self.send.nxt < ackn {
                return Ok(());
            }
        } else {
            // check is okay iff SND.NXT is between SND.UNA and SEG.ACK
            if self.send.nxt >= ackn && self.send.nxt < self.send.una {
            } else {
                return Ok(());
            }
        }

        if !(self.send.una < ackn && ackn <= self.send.nxt) {
            return Ok(());
        }
        match self.state {
            State::SynRcvd => {
                // expect to get an ACK for out SYN
            }
            State::Estab => {
                unimplemented!();
            }
        }
        Ok(())
    }
}

use std::fmt;

// https://tools.ietf.org/html/rfc793#section-3.2 [Page 22]
enum State {
    // Closed,
    // Listen,
    SynRcvd,
    Estab,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    TimeWait,
}

impl State {
    fn is_synchronized(&self) -> bool {
        match *self {
            State::SynRcvd => false,
            State::Estab | State::FinWait1 | State::FinWait2 | State::CloseWait | State::Closing => true,
        }
    }
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        match *self {
            State::SynRcvd => write!(f, "SynRcvd"),
            State::Estab => write!(f, "Estab"),
        }
    }
}

pub struct Connection {
    state: State,
    send: SendSequenceSpace,
    recv: ReceiveSequenceSpace,
    ip: etherparse::Ipv4Header,
    tcp: etherparse::TcpHeader,
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
        &mut self,
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
        let wnd = 10;
        let mut conn = Connection {
            state: State::SynRcvd,
            send: SendSequenceSpace {
                iss,
                una: iss,
                nxt: iss,
                wnd: wnd,
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
            tcp: etherparse::TcpHeader::new(tcph.destination_port(), tcph.source_port(), iss, wnd),
        };

        // need to start to establishing a connection
        self.tcp.syn = true;
        self.tcp.ack = true;
        conn.write(iface, &[])?;
        Ok(Some(conn))
    }

    fn write(&mut self, iface: &mut tun_tap::Iface, payload: &[u8]) -> std::io::Result<usize> {
        let mut buf = [0u8; 1500];
        self.tcp.sequence_number = self.send.nxt;
        self.tcp.acknowledgment_number = self.recv.nxt;

        //  The buffer set the max size to send in a packet (MTU)
        let size = std::cmp::min(
            buf.len(),
            self.ip.header_len() as usize + self.tcp.header_len() as usize + payload.len(),
        );

        self.ip.set_payload_len(size);

        // Checksum computation
        self.tcp.checksum = self
            .tcp
            .calc_checksum_ipv4(&self.ip, &[])
            .expect("failed to compute checksum");

        use std::io::Write;
        let mut unwritten = &mut buf[..];
        self.ip
            .write(&mut unwritten)
            .expect("failed writing ip header to buffer");
        self.tcp
            .write(&mut unwritten)
            .expect("failed writing tcp header to buffer");
        let payload_bytes = unwritten.write(payload)?;
        let unwritten = unwritten.len();

        // Increment sequence number
        self.send.nxt.wrapping_add(payload_bytes as u32);
        if self.tcp.syn {
            self.send.nxt = self.send.nxt.wrapping_add(1);
            self.tcp.syn = false;
        }
        if self.tcp.fin {
            self.send.nxt = self.send.nxt.wrapping_add(1);
            self.tcp.fin = false;
        }
        iface.send(&buf[..buf.len() - unwritten]);
        Ok(payload_bytes)
    }

    fn send_rst(&mut self, iface: &mut tun_tap::Iface) -> std::io::Result<()> {
        self.tcp.rst = true;
        // TODO: fix sequence numbers here
        // If the incoming segment has an ACK field, the reset takes its
        // sequence number from the ACK field of the segment, otherwise the
        //     reset has sequence number zero and the ACK field is set to the sum
        //     of the sequence number and segment length of the incoming segment.
        //     The connection remains in the CLOSED state.
        // TODO: handle syncronized RST
        // 3.  If the connection is in a synchronized state (FIN-WAIT-1, FIN-WAIT-2,
        // CLOSE-WAIT, CLOSING, LAST-ACK, TIME-WAIT), any unacceptable segment (out of
        // window sequence number or unacceptible acknowledgment number) must elicit
        // only an empty acknowledgment segment containing the current send-sequence
        // number and an acknowledgment indicating the next sequence number expected
        // to be received, and the connection remains in the same state.
        self.tcp.sequence_number = 0;
        self.tcp.acknowledgment_number = 0;
        self.ip.set_payload_len(self.tcp.header_len() as usize);
        self.write(iface, &[])?;
        Ok(())
    }

    pub fn on_packet<'a>(
        &mut self,
        iface: &mut tun_tap::Iface,
        iph: etherparse::Ipv4HeaderSlice<'a>,
        tcph: etherparse::TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> std::io::Result<()> {
        // First, valid segment check (RFC 793 S3.3 P25)
        //
        // ```
        // A segment is judged to occupy a portion of valid receive sequence
        // space if
        //
        // RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
        //
        // or
        //
        // RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
        //
        // The first part of this test checks to see if the beginning of the
        // segment falls in the window, the second part of the test checks to see
        // if the end of the segment falls in the window;
        // ```
        let seqn = tcph.sequence_number();
        // ```
        // SEG.LEN = the number of octets occupied by the data in the segment
        //      (counting SYN and FIN)
        // ```
        let mut slen = data.len() as u32;
        if tcph.syn() {
            slen += 1;
        }
        if tcph.fin() {
            slen += 1;
        }
        let wend = self.recv.nxt.wrapping_add(self.recv.wnd as u32);
        // zero-length segment has separate rules for acceptance (RFC 793 S3.3 P26)
        //
        // ```
        // Actually, it is a little more complicated than this.  Due to zero
        // windows and zero length segments, we have four cases for the
        // acceptability of an incoming segment:
        //
        //  Segment Receive  Test
        //  Length  Window
        //  ------- -------  -------------------------------------------
        //
        //      0       0     SEG.SEQ = RCV.NXT
        //
        //      0      >0     RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
        //
        //     >0       0     not acceptable
        //
        //     >0      >0     RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
        //                 or RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
        //
        // Note that when the receive window is zero no segments should be
        // acceptable except ACK segments.
        // ```
        println!(
            "DPORT={}, STATE={}, SYN={}, ACK={}, FIN={}, SEG.LEN={}, RCV.NXT={}, SEG.SEC={}, WEND={}, RCV.WND={}",
            tcph.destination_port(),
            self.state,
            tcph.syn(),
            tcph.ack(),
            tcph.fin(),
            slen,
            self.recv.nxt.wrapping_sub(1),
            seqn,
            self.recv.wnd,
            wend
        );
        if slen == 0 {
            if self.recv.wnd == 0 {
                if seqn != self.recv.nxt {
                    return Ok(());
                }
            } else if !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, wend) {
                return Ok(());
            }
        } else if self.recv.wnd == 0
            || !(is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, wend)
                 || is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn.wrapping_add(slen - 1), wend))
        {
            return Ok(());
        }
        // The next sequence number expected
        self.recv.nxt = seqn.wrapping_add(slen);

        // TODO: if _not_ acceptable send ACK
        // ```
        // If an incoming segment is not acceptable, an acknowledgment
        //     should be sent in reply (unless the RST bit is set, if so drop
        //                              the segment and return):
        //
        // <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
        // ``

        // Second, valid sequence numbers check (RFC 793 S3.3 P24)
        //
        // ```
        // A new acknowledgment (called an "acceptable ack"), is one for which
        // the inequality below holds:
        //
        // SND.UNA < SEG.ACK =< SND.NXT
        // ```
        let ackn = tcph.acknowledgment_number();
        if !is_between_wrapped(self.send.una, ackn, self.send.nxt.wrapping_add(1)) {
            if !self.state.is_synchronized() {
                // according to Reset Generation, we should send a RST (RFC 793 S3.4 P36)
                self.send_rst(iface);
            }
            return Ok(());
        }
        // the next byte is expect, the first byte unacknowledged
        self.send.una = ackn;

        match self.state {
            State::SynRcvd => {
                // expect to get an ACK for our SYN
                if !tcph.ack() {
                    return Ok(());
                }
                // must have ACKed our SYN, since we detected at least one acked byte,
                // and we have only sent one byte (the SYN).
                self.state = State::Estab;

                // now let's terminate the connection!
                // TODO: needs tobe stored in the retransmission queue!
                self.tcp.fin = true;
                self.write(iface, &[]);

                self.state = State::FinWait1;
            }
            State::Estab => {
                unimplemented!();
            }
            State::FinWait1 => {
                if !tcph.fin() || !data.is_empty() {
                    unimplemented!();
                }
                // must have ACKed our FIN, since we detected at least one acked byte,
                // and we have only sent one byte (the FIN).
                self.state = State::FinWait2;
            }
            State::FinWait2 => {
                self.tcp.fin = false;
                self.write(iface, &[]);
                self.state = State::TimeWait;
            }
        }
        Ok(())
    }
}

fn is_between_wrapped(start: u32, x: u32, end: u32) -> bool {
    use std::cmp::Ordering;
    match start.cmp(&x) {
        Ordering::Equal => false,
        Ordering::Less => {
            // we have:
            //
            //     0 |-------------S------X-------------------| (wraparound)
            //
            // X is between S and E (S < X < E) in these cases:
            //
            //     0 |--------------S------X----E-------------| (wraparound)
            //
            //     0 |----------E---S------X------------------| (wraparound)
            //
            // but *not* in these cases
            //
            //     0 |----------S------E---X------------------| (wraparound)
            //
            //     0 |----------|----------X------------------| (wraparound)
            //                  ^-S+E
            //
            //     0 |----------S----------|------------------| (wraparound)
            //                         X+E-^
            //
            // or, in other words, iff !(S <= E <= X)
            !(end >= start && end <= x)
        }
        Ordering::Greater => {
            // we have the opposite of above:
            //
            //    0 |-------------X------S-------------------| (wraparound)
            //
            // X is between S and E (S < X < E) *only* in this case:
            //
            //    0 |--------------X-----E-----S-------------| (wraparound)
            //
            // but *not* in these cases
            //
            //    0 |------------X----S---E------------------| (wraparound)
            //
            //    0 |--------E---X----S----------------------| (wraparound)
            //
            //    0 |----------|----------S------------------| (wraparound)
            //                 ^-X+E
            //p
            //    0 |----------X----------|------------------| (wraparound)
            //                        S+E-^
            //
            // or, in other words, iff S < E < X
            end < start && end > x
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_between_wrapped_test() {
        std::char::from_u32(34);
        // start == x, *not* in between
        assert!(!is_between_wrapped(10, 10, 11));

        // start < x:
        // S---X---E
        assert!(is_between_wrapped(10, 11, 12));
        // E---S---X
        assert!(is_between_wrapped(10, 11, 9));
        // S---E---X
        assert!(!is_between_wrapped(10, 12, 11));
        // S+E---X
        assert!(!is_between_wrapped(10, 11, 10));
        // S---X+E
        assert!(!is_between_wrapped(10, 11, 11));

        // x < start:
        // only valid case
        assert!(is_between_wrapped(10, 8, 9));
        // X---S---E
        assert!(!is_between_wrapped(10, 9, 11));
        // E---X---S
        assert!(!is_between_wrapped(10, 9, 8));
        // x+E---S
        assert!(!is_between_wrapped(10, 9, 9));
        // X---S+E
        assert!(!is_between_wrapped(9, 10, 9));
    }
}

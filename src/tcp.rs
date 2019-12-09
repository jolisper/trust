// https://tools.ietf.org/html/rfc793#section-3.2 [Page 22]
pub enum State {
    Closed,
    Listen,
    SynRcvd,
    Estab,
}

impl Default for State {
    fn default() -> Self {
        // Assumed that all ports all listening for now
        State::Listen
    }
}

impl State {
    pub fn on_packet<'a>(
        &mut self,
        iph: etherparse::Ipv4HeaderSlice<'a>,
        tcph: etherparse::TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) {
        eprintln!(
            "{}:{} -> {}:{} {} bytes of tcp",
            iph.source_addr(),
            tcph.source_port(),
            iph.destination_addr(),
            tcph.destination_port(),
            data.len(),
        );
    }
}

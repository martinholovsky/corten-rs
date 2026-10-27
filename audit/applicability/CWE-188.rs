//@ compiles: safe
// CWE-188, reliance on data layout: assumes the IPv4 header is always 20
// bytes, ignoring the IHL field, so options are read as payload.
pub fn payload(packet: &[u8]) -> &[u8] {
    &packet[20..]
}

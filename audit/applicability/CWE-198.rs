//@ compiles: safe
// CWE-198, incorrect byte ordering: a big-endian length field from the network
// is decoded with native (little-endian on x86/ARM) order.
pub fn length_field(hdr: &[u8; 4]) -> u32 {
    u32::from_ne_bytes(*hdr)
}

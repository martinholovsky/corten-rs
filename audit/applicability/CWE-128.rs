//@ compiles: safe
// CWE-128, wrap-around error. With overflow-checks off (the release-profile
// default) `+= 1` on a u8 sequence number wraps 255 -> 0, and the replay check
// then accepts an old message.
pub struct Session { pub last_seq: u8 }
pub fn accept(s: &mut Session, seq: u8) -> bool {
    let expected = s.last_seq + 1;
    if seq == expected { s.last_seq = seq; true } else { false }
}

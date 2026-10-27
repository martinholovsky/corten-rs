//@ compiles: safe
// CWE-226, sensitive information not removed before reuse. Pooled buffers go
// back to the pool unzeroed and the whole buffer is sent, so a short reply
// carries the previous user's bytes after it.
pub struct Pool {
    pub free: Vec<Box<[u8; 64]>>,
}
pub fn respond(pool: &mut Pool, msg: &[u8]) -> Vec<u8> {
    let mut b = pool.free.pop().unwrap_or_else(|| Box::new([0; 64]));
    b[..msg.len()].copy_from_slice(msg);
    let out = b.to_vec();
    pool.free.push(b);
    out
}

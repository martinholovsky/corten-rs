//! SHA-256 (FIPS 180-4), for provenance digests without a dependency.

const K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

const H0: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

#[expect(
    clippy::many_single_char_names,
    reason = "FIPS 180-4 names the working variables a to h; matching it eases review"
)]
fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 64];
    let (words, _) = block.as_chunks::<4>();
    for (slot, bytes) in w.iter_mut().zip(words) {
        *slot = u32::from_be_bytes(*bytes);
    }
    for i in 16usize..64 {
        let at = |k: usize| w.get(k).copied().unwrap_or(0);
        let (w15, w2) = (at(i.wrapping_sub(15)), at(i.wrapping_sub(2)));
        let s0 = w15.rotate_right(7) ^ w15.rotate_right(18) ^ (w15 >> 3);
        let s1 = w2.rotate_right(17) ^ w2.rotate_right(19) ^ (w2 >> 10);
        let value = at(i.wrapping_sub(16))
            .wrapping_add(s0)
            .wrapping_add(at(i.wrapping_sub(7)))
            .wrapping_add(s1);
        if let Some(slot) = w.get_mut(i) {
            *slot = value;
        }
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for (k, wi) in K.iter().zip(w.iter()) {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let t1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(*k)
            .wrapping_add(*wi);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    for (s, v) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *s = s.wrapping_add(v);
    }
}

/// The SHA-256 digest of `data`.
#[must_use]
pub fn digest(data: &[u8]) -> [u8; 32] {
    let mut state = H0;
    let (blocks, rest) = data.as_chunks::<64>();
    for block in blocks {
        compress(&mut state, block);
    }
    let mut tail = [0u8; 128];
    let tail_len: usize = if rest.len() < 56 { 64 } else { 128 };
    if let Some(dst) = tail.get_mut(..rest.len()) {
        dst.copy_from_slice(rest);
    }
    if let Some(byte) = tail.get_mut(rest.len()) {
        *byte = 0x80;
    }
    let bit_len = u64::try_from(data.len())
        .unwrap_or(u64::MAX)
        .wrapping_mul(8);
    if let Some(dst) = tail.get_mut(tail_len.wrapping_sub(8)..tail_len) {
        dst.copy_from_slice(&bit_len.to_be_bytes());
    }
    let (tail_blocks, _) = tail.get(..tail_len).unwrap_or(&[]).as_chunks::<64>();
    for block in tail_blocks {
        compress(&mut state, block);
    }
    let mut out = [0u8; 32];
    let (out_words, _) = out.as_chunks_mut::<4>();
    for (dst, word) in out_words.iter_mut().zip(state) {
        *dst = word.to_be_bytes();
    }
    out
}

/// The digest as lowercase hexadecimal.
#[must_use]
pub fn hex_digest(data: &[u8]) -> String {
    digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .concat()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FIPS 180-4 / NIST CAVP example vectors.
    #[test]
    fn nist_vectors() {
        assert_eq!(
            hex_digest(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex_digest(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex_digest(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        assert_eq!(
            hex_digest(&vec![b'a'; 1_000_000]),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn padding_boundaries() {
        // 55, 56, 63 and 64 bytes straddle the one- and two-block padding.
        for len in [55usize, 56, 63, 64, 119, 120] {
            let d = digest(&vec![0x61; len]);
            assert_ne!(d, [0u8; 32], "{len}");
        }
        assert_eq!(
            hex_digest(&[0x61; 56]),
            "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a"
        );
    }
}

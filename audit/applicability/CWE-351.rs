//@ compiles: safe
// CWE-351, insufficient type distinction. Both user ids and group ids are
// bare u32, so a caller can pass a group id where a user id is expected
// and the check grants access. Newtypes would distinguish them; Rust does
// not require them.
pub fn is_root(uid: u32) -> bool { uid == 0 }
pub fn may_administer(gid_of_request: u32) -> bool {
    is_root(gid_of_request)
}

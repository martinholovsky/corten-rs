//@ compiles: safe
// CWE-431, missing handler: exhaustive matching forces an arm per enum variant,
// but the wildcard arm leaves the revocation event with no handler.
pub fn on_event(kind: u8, sessions: &mut Vec<u32>, id: u32) {
    match kind {
        1 => sessions.push(id),
        _ => {}
    }
}

//@ compiles: safe
// CWE-464, addition of a data-structure sentinel. Rule ids are kept in a
// list terminated by END; a user-supplied rule id of 0 is inserted unchecked
// and becomes a second terminator, so the deny rules after it stop applying.
pub const END: u32 = 0;
// User rules go in front of the built-in deny rules.
pub fn add_user_rule(rules: &mut Vec<u32>, rule: u32) {
    rules.insert(0, rule);
}
pub fn active(rules: &[u32]) -> Vec<u32> {
    rules.iter().copied().take_while(|&r| r != END).collect()
}

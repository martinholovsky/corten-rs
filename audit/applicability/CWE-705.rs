//@ compiles: safe
// CWE-705, incorrect control flow scoping: library code exits the whole process
// on a bad record instead of returning control to the caller.
pub fn parse_record(line: &str) -> u32 {
    match line.trim().parse() {
        Ok(v) => v,
        Err(_) => std::process::exit(1),
    }
}

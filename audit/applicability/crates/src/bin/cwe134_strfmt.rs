#![forbid(unsafe_code)]
// CWE-134: the format string comes from outside.
fn main() {
    let fmt = std::env::args().nth(1).unwrap_or_else(|| "{secret}".to_owned());
    let mut vars = std::collections::HashMap::new();
    vars.insert("secret".to_owned(), "s3cr3t");
    vars.insert("name".to_owned(), "alice");
    println!("{}", strfmt::strfmt(&fmt, &vars).unwrap());
}

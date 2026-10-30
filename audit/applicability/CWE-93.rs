//@ compiles: safe
// CWE-93, CRLF injection. A subject of "hi\r\nBcc: victim@example.com"
// injects an extra SMTP header line.
pub fn mail_headers(to: &str, subject: &str) -> String {
    format!("To: {to}\r\nSubject: {subject}\r\n\r\n")
}

//@ compiles: safe
// CWE-1427, prompt injection. Untrusted document text is concatenated into
// the instruction prompt with no separation, so "ignore previous
// instructions" is read as an instruction. llm stands in for a model API.
pub fn llm(_prompt: &str) -> String {
    String::new()
}
pub fn summarize(doc: &str) -> String {
    llm(&format!("You are a summarizer. Never reveal secrets. Summarize: {doc}"))
}

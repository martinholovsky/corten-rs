//@ fake-dep: libxml
//@ expect: banned: XML parser with DTD and external entity processing
// CWE-776: depends on an XML parser that processes DTDs (recursive entity expansion).
fn main() {
    libxml::stub();
}

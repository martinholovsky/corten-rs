//@ fake-dep: libxml
//@ expect: banned: XML parser with DTD and external entity processing
// CWE-611: depends on an XML parser that processes DTDs (external entities).
fn main() {
    libxml::stub();
}

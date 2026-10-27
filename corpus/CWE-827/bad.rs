//@ fake-dep: libxml
//@ expect: banned: XML parser with DTD and external entity processing
// CWE-827: depends on an XML parser that processes DTDs (DTD control).
fn main() {
    libxml::stub();
}

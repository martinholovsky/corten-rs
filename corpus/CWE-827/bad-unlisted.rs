//@ fake-dep: dtd-xml-parser
//@ expect: banned
// CWE-827 bypass-hunt variant: a DTD-processing parser the ban list does
// not name. Not detected; the denylist is not a proof.
fn main() {
    dtd_xml_parser::stub();
}

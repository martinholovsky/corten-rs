//@ expect: expected
//@ absent
// CWE-491: a public cloneable() method that is not final.
public class Session implements Cloneable {
    public Object clone() { return this; }
}
fn main() {}

// @rejected: incompatible types: Integer cannot be converted to String
// CWE-843: a cast between unrelated types is rejected; a checked cast between related ones throws ClassCastException.
class P {
    static String f() {
        Integer i = 1;
        return (String) i;
    }
}

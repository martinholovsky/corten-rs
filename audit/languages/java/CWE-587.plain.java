// @rejected: incompatible types: int cannot be converted to int[]
// CWE-587: an integer cannot be converted to a reference.
class P {
    static int[] f() {
        return (int[]) 0x1000;
    }
}

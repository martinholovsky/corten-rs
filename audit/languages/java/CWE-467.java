// @rejected: cannot find symbol
// CWE-467: Java has no sizeof operator.
class P {
    static int f(int[] key) {
        return sizeof(key);
    }
}

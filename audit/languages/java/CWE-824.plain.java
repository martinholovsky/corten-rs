// @rejected: variable x might not have been initialized
// CWE-824: javac's definite-assignment check rejects reading a local before it is set.
class P {
    static int f() {
        int x;
        return x;
    }
}

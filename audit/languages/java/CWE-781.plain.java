// @rejected: cannot find symbol
// CWE-781: plain Java cannot call a C function; there is no such method.
class P {
    static void f() {
        gets(new byte[8]);
    }
}

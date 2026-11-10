// @compiles
// CWE-1058: a method called from threads modifies a non-final static.
class P {
    static int calls;

    static int handle() {
        return ++calls;
    }
}

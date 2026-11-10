// @compiles: hatch
// CWE-558: libc's getlogin, with its shared static buffer, is reached through a native method.
class P {
    static native long getlogin();
}

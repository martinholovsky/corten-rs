// @compiles: hatch
// CWE-785: libc's realpath writing into a caller buffer is reached through a native method.
class P {
    static native long realpath(byte[] path, long out);
}

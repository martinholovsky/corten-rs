// @compiles: hatch
// CWE-111: a native method runs C code through JNI with none of Java's checks.
class P {
    static native int strlen(byte[] s);
}

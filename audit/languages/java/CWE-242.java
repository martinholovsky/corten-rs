// @compiles: hatch
// CWE-242: libc's gets is reached through a native method.
class P {
    static native long gets(byte[] buf);
}

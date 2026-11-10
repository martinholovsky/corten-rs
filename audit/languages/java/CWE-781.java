// @compiles: hatch
// CWE-781: an IOCTL-style handler in native code takes a raw user address; Java reaches it only through JNI.
class P {
    static native int deviceIoControl(long handle, int code, long userBuffer, int length);
}

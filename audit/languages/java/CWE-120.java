// @compiles: hatch
// CWE-120: input bytes are copied into a 16-byte block with no length check.
import java.lang.reflect.Field;
import sun.misc.Unsafe;

class P {
    static final Unsafe U = unsafe();

    static Unsafe unsafe() {
        try {
            Field f = Unsafe.class.getDeclaredField("theUnsafe");
            f.setAccessible(true);
            return (Unsafe) f.get(null);
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException(e);
        }
    }

    static void f(byte[] in) {
        long dst = U.allocateMemory(16);
        for (int i = 0; i < in.length; i++) U.putByte(dst + i, in[i]);
        U.freeMemory(dst);
    }
}

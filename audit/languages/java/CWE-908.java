// @compiles: hatch
// CWE-908: an uninitialised off-heap buffer is read.
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

    static byte f() {
        long p = U.allocateMemory(64);
        byte b = U.getByte(p + 10);
        U.freeMemory(p);
        return b;
    }
}

// @compiles: hatch
// CWE-125: an off-heap block is read at an unchecked index.
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

    static int f(int i) {
        long p = U.allocateMemory(16);
        int v = U.getInt(p + 4L * i);
        U.freeMemory(p);
        return v;
    }
}

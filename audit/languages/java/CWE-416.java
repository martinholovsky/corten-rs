// @compiles: hatch
// CWE-416: an off-heap block is read after it is freed.
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

    static int f() {
        long p = U.allocateMemory(4);
        U.putInt(p, 42);
        U.freeMemory(p);
        return U.getInt(p);
    }
}

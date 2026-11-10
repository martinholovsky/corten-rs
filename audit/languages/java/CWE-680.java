// @compiles: hatch
// CWE-680: n * 4 wraps to a small allocation, and n ints are then written.
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

    static void f(int n) {
        long p = U.allocateMemory(n * 4);
        for (int i = 0; i < n; i++) U.putInt(p + 4L * i, 0);
        U.freeMemory(p);
    }
}

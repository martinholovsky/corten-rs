// @compiles: hatch
// CWE-122: an off-heap block is written past its end.
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
        long p = U.allocateMemory(4);
        U.setMemory(p, n, (byte) 0);
        U.freeMemory(p);
    }
}

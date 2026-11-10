// @compiles: hatch
// CWE-787: an off-heap block is written at an unchecked index.
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

    static void f(int i, int v) {
        long p = U.allocateMemory(32);
        U.putInt(p + 4L * i, v);
        U.freeMemory(p);
    }
}

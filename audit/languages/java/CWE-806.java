// @compiles: hatch
// CWE-806: a copy uses the source's size for a smaller destination.
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

    static void f(long src) {
        long small = U.allocateMemory(4);
        U.copyMemory(src, small, 64);
        U.freeMemory(small);
    }
}

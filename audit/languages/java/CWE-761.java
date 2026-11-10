// @compiles: hatch
// CWE-761: freeMemory is given a pointer into the middle of a block.
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

    static void f() {
        long p = U.allocateMemory(16);
        U.freeMemory(p + 4);
    }
}

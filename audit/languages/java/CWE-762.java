// @compiles: hatch
// CWE-762: a block from allocateMemory is released with a different routine (reallocateMemory to zero, then freeMemory).
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
        long q = U.reallocateMemory(p, 0);
        U.freeMemory(p);
    }
}

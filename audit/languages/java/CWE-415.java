// @compiles: hatch
// CWE-415: the same off-heap block is freed twice.
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
        long p = U.allocateMemory(8);
        U.freeMemory(p);
        U.freeMemory(p);
    }
}

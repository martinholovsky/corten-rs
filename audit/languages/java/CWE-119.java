// @compiles: hatch
// CWE-119: a loop writes one long past an 8-byte off-heap block.
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
        long a = U.allocateMemory(8);
        for (int i = 0; i <= 1; i++) U.putLong(a + 8L * i, i);
        U.freeMemory(a);
    }
}

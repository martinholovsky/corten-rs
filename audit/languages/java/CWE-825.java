// @compiles: hatch
// CWE-825: a stored address is used after its block is freed.
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

    static long saved;

    static int f() {
        long p = U.allocateMemory(4);
        saved = p;
        U.freeMemory(p);
        return U.getInt(saved);
    }
}

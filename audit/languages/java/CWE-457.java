// @compiles: hatch
// CWE-457: allocateMemory returns uninitialised memory, which is read.
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
        long p = U.allocateMemory(16);
        int x = U.getInt(p + 8);
        U.freeMemory(p);
        return x;
    }
}

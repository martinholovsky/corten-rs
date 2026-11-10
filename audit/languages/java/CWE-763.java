// @compiles: hatch
// CWE-763: freeMemory is given an address computed from an object offset.
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

    static void f(Object o) throws NoSuchFieldException {
        long off = U.objectFieldOffset(P.class.getDeclaredField("U"));
        U.freeMemory(off);
    }
}

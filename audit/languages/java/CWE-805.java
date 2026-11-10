// @compiles: hatch
// CWE-805: copyMemory is given a length unrelated to the destination's size.
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

    static void f(long src, long n) {
        long dst = U.allocateMemory(8);
        U.copyMemory(src, dst, n);
        U.freeMemory(dst);
    }
}

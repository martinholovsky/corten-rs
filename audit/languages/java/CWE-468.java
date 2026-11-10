// @compiles: hatch
// CWE-468: an index is scaled twice: by hand, and by the element size again.
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

    static int f(long base, long i) {
        return U.getInt(base + i * 4 * 4);
    }
}

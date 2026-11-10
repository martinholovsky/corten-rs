// @compiles: hatch
// CWE-824: an address field read from uninitialised memory is dereferenced.
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
        long holder = U.allocateMemory(8);
        long p = U.getLong(holder);
        return U.getInt(p);
    }
}

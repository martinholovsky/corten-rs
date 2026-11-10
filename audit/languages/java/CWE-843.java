// @compiles: hatch
// CWE-843: an object reference is read back as a long through putObject and getLong.
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

    static long f(Object o) {
        long p = U.allocateMemory(8);
        U.putLong(p, 0);
        long[] holder = new long[1];
        U.putObject(holder, (long) Unsafe.ARRAY_LONG_BASE_OFFSET, o);
        long bits = holder[0];
        U.freeMemory(p);
        return bits;
    }
}

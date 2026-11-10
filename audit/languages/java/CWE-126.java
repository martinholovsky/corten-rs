// @compiles: hatch
// CWE-126: a read continues past the end of an off-heap block.
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

    static long f(long p, long len) {
        long s = 0;
        for (long i = 0; i < len + 8; i++) s += U.getByte(p + i);
        return s;
    }
}

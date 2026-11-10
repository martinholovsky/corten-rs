// @compiles: hatch
// CWE-170: a C-style string in native memory is scanned for a terminator that was never written.
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
        long p = U.allocateMemory(8);
        U.setMemory(p, 8, (byte) 'a');
        int n = 0;
        while (U.getByte(p + n) != 0) n++;
        U.freeMemory(p);
        return n;
    }
}

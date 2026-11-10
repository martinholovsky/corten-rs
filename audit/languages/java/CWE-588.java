// @compiles: hatch
// CWE-588: a block holding one int is read as a two-field record.
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
        long p = U.allocateMemory(4);
        int type = U.getInt(p + 4);
        U.freeMemory(p);
        return type;
    }
}

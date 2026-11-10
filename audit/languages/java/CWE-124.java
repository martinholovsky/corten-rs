// @compiles: hatch
// CWE-124: a write lands before the start of an off-heap block.
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

    static void f(int i) {
        long p = U.allocateMemory(8);
        U.putByte(p + i - 8, (byte) 0);
        U.freeMemory(p);
    }
}

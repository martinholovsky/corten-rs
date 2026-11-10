// @compiles: hatch
// CWE-121: Java has no stack arrays; a write to an arbitrary address can still reach the stack.
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

    static void f(long addr, long len) {
        U.setMemory(addr, len, (byte) 0x41);
    }
}

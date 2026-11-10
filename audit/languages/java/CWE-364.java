// @compiles: hatch
// CWE-364: the handler, on its own thread, frees state the main code still uses.
import sun.misc.Signal;

class P {
    static byte[] buf = new byte[64];

    static void f() {
        Signal.handle(new Signal("TERM"), s -> buf = null);
        buf[0] = 1;
    }
}

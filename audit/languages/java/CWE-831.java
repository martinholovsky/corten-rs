// @compiles: hatch
// CWE-831: one non-reentrant handler serves two signals, each dispatched on its own thread.
import sun.misc.Signal;

class P {
    static StringBuilder log = new StringBuilder();

    static void f() {
        Signal.handle(new Signal("HUP"), s -> log.append(s));
        Signal.handle(new Signal("TERM"), s -> log.append(s));
    }
}

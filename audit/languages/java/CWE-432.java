// @compiles: hatch
// CWE-432: the handler stays installed while shared state is half-updated.
import sun.misc.Signal;

class P {
    static int a, b;

    static void f() {
        Signal.handle(new Signal("INT"), s -> System.out.println(a + " " + b));
        a = 1;
        b = 1;
    }
}

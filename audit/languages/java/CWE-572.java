// @compiles
// CWE-572: Thread.run() runs the body on the calling thread; start() was meant.
class P {
    static void f() {
        new Thread(() -> {}).run();
    }
}

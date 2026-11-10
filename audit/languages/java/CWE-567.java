// @compiles
// CWE-567: two threads increment an unsynchronised field.
class P {
    static long counter;

    static void f() throws InterruptedException {
        Runnable r = () -> { for (int i = 0; i < 1000; i++) counter++; };
        Thread a = new Thread(r), b = new Thread(r);
        a.start(); b.start();
        a.join(); b.join();
    }
}

// @compiles
// CWE-586: finalize() is called explicitly, then again by the garbage collector.
class P {
    static class Conn {
        @Override
        @SuppressWarnings("removal")
        protected void finalize() {}

        @SuppressWarnings("removal")
        void close() {
            finalize();
        }
    }
}

// @compiles
// CWE-584: a return in finally discards the exception thrown in try.
class P {
    @SuppressWarnings("finally")
    static int f() {
        try {
            throw new IllegalStateException();
        } finally {
            return 0;
        }
    }
}

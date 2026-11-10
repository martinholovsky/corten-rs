// @rejected: cannot find symbol
// CWE-762: plain Java has no free(); memory is released only by the garbage collector.
class P {
    static void f(Object p) {
        free(p);
    }
}

// @compiles
// CWE-1056: a varargs method reads as many ints as the caller passes.
class P {
    static int sum(int... xs) {
        int s = 0;
        for (int x : xs) s += x;
        return s;
    }
}

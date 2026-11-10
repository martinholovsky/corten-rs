// @compiles
// CWE-483: the second statement looks guarded but always runs.
class P {
    static int f(boolean ok) {
        int granted = 0;
        if (ok)
            granted = 1;
            granted = 2;
        return granted;
    }
}

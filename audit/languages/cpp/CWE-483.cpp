// @compiles
// CWE-483: the second statement looks guarded but always runs.

int f(int ok) {
    int granted = 0;
    if (ok)
        granted = 1;
        granted = 2;
    return granted;
}

// @compiles
// CWE-761: delete[] is given a pointer that is not the start of the array.
void f() {
    char *p = new char[16];
    delete[] (p + 4);
}

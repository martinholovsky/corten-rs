// @compiles
// CWE-242: gets() is gone from C++14's <cstdio>; it is declared by hand with
// C linkage and called.
extern "C" char *gets(char *s);

void read_line() {
    char buf[64];
    gets(buf);
}

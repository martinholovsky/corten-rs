// @compiles
// CWE-242: gets() is declared by hand, since C17 headers no longer provide it, and called.
char *gets(char *s);

void read_line(void) {
    char buf[64];
    gets(buf);
}

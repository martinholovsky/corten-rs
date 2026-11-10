// @compiles
// CWE-499: the whole session struct, password included, is written to a file.
#include <stdio.h>

struct session { char user[32]; char password[32]; };

void save(const struct session *s, FILE *fp) {
    fwrite(s, sizeof *s, 1, fp);
}

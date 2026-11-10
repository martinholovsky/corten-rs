# @rejected: invalid syntax
# CWE-558: plain Python cannot declare or call a C function; the C declaration does not parse.

extern char *gets(char *s);

// @compiles
// CWE-781: an IOCTL-style handler reads through a user-supplied address unchecked.
#include <stdint.h>

struct request { uintptr_t user_buffer; unsigned length; };

unsigned char handle(const struct request *r) {
    const unsigned char *p = (const unsigned char *)r->user_buffer;
    return p[r->length - 1];
}

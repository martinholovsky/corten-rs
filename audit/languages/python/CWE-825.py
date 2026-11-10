# @compiles: hatch
# CWE-825: an address is used after its block is freed.
import ctypes

libc = ctypes.CDLL(None)
libc.malloc.restype = ctypes.c_void_p
libc.malloc.argtypes = [ctypes.c_size_t]
libc.free.argtypes = [ctypes.c_void_p]


saved = 0


def f() -> int:
    global saved
    p = libc.malloc(4)
    saved = p
    libc.free(p)
    return ctypes.c_int.from_address(saved).value

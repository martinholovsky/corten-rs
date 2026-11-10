# @compiles: hatch
# CWE-908: an uninitialised malloc'd buffer is read.
import ctypes

libc = ctypes.CDLL(None)
libc.malloc.restype = ctypes.c_void_p
libc.malloc.argtypes = [ctypes.c_size_t]
libc.free.argtypes = [ctypes.c_void_p]


def f() -> bytes:
    p = libc.malloc(64)
    b = ctypes.string_at(p + 10, 1)
    libc.free(p)
    return b

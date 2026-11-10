# @compiles: hatch
# CWE-122: a malloc'd block is written past its end.
import ctypes

libc = ctypes.CDLL(None)
libc.malloc.restype = ctypes.c_void_p
libc.malloc.argtypes = [ctypes.c_size_t]
libc.free.argtypes = [ctypes.c_void_p]


def f(n: int):
    p = libc.malloc(4)
    ctypes.memset(p, 0, n)
    libc.free(p)

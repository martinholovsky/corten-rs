# @compiles: hatch
# CWE-415: the same malloc'd block is freed twice.
import ctypes

libc = ctypes.CDLL(None)
libc.malloc.restype = ctypes.c_void_p
libc.malloc.argtypes = [ctypes.c_size_t]
libc.free.argtypes = [ctypes.c_void_p]


def f():
    p = libc.malloc(8)
    libc.free(p)
    libc.free(p)

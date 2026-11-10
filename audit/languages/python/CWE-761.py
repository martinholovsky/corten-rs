# @compiles: hatch
# CWE-761: free is given a pointer into the middle of a block.
import ctypes

libc = ctypes.CDLL(None)
libc.malloc.restype = ctypes.c_void_p
libc.malloc.argtypes = [ctypes.c_size_t]
libc.free.argtypes = [ctypes.c_void_p]


def f():
    p = libc.malloc(16)
    libc.free(p + 4)

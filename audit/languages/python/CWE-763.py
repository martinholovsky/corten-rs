# @compiles: hatch
# CWE-763: free is given an address malloc never returned.
import ctypes

libc = ctypes.CDLL(None)
libc.malloc.restype = ctypes.c_void_p
libc.malloc.argtypes = [ctypes.c_size_t]
libc.free.argtypes = [ctypes.c_void_p]


def f(obj):
    libc.free(id(obj))

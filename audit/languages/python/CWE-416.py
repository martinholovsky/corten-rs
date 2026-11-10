# @compiles: hatch
# CWE-416: a malloc'd block is read after it is freed.
import ctypes

libc = ctypes.CDLL(None)
libc.malloc.restype = ctypes.c_void_p
libc.malloc.argtypes = [ctypes.c_size_t]
libc.free.argtypes = [ctypes.c_void_p]


def f() -> int:
    p = libc.malloc(4)
    ctypes.c_int.from_address(p).value = 42
    libc.free(p)
    return ctypes.c_int.from_address(p).value

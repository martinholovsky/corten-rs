# @compiles: hatch
# CWE-457: malloc returns uninitialised memory, which is read.
import ctypes

libc = ctypes.CDLL(None)
libc.malloc.restype = ctypes.c_void_p
libc.malloc.argtypes = [ctypes.c_size_t]
libc.free.argtypes = [ctypes.c_void_p]


def f() -> int:
    p = libc.malloc(16)
    x = ctypes.c_int.from_address(p + 8).value
    libc.free(p)
    return x

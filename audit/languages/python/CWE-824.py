# @compiles: hatch
# CWE-824: a pointer read from uninitialised malloc'd memory is dereferenced.
import ctypes

libc = ctypes.CDLL(None)
libc.malloc.restype = ctypes.c_void_p
libc.malloc.argtypes = [ctypes.c_size_t]
libc.free.argtypes = [ctypes.c_void_p]


def f() -> int:
    holder = libc.malloc(8)
    p = ctypes.c_void_p.from_address(holder).value
    return ctypes.c_int.from_address(p).value

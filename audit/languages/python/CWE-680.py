# @compiles: hatch
# CWE-680: n * 4 wraps in a 32-bit size, giving a small allocation that n ints are written into.
import ctypes

libc = ctypes.CDLL(None)
libc.malloc.restype = ctypes.c_void_p
libc.malloc.argtypes = [ctypes.c_size_t]
libc.free.argtypes = [ctypes.c_void_p]


def f(n: int):
    size = ctypes.c_uint32(n * 4).value
    p = libc.malloc(size)
    for i in range(n):
        ctypes.c_int.from_address(p + 4 * i).value = 0
    libc.free(p)

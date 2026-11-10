# @compiles: hatch
# CWE-762: a block from malloc is released with munmap instead of free.
import ctypes

libc = ctypes.CDLL(None)
libc.malloc.restype = ctypes.c_void_p
libc.malloc.argtypes = [ctypes.c_size_t]
libc.free.argtypes = [ctypes.c_void_p]


def f():
    p = libc.malloc(4096)
    libc.munmap(ctypes.c_void_p(p), ctypes.c_size_t(4096))

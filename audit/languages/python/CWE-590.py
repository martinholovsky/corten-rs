# @compiles: hatch
# CWE-590: free is given the address of a ctypes buffer Python owns.
import ctypes

libc = ctypes.CDLL(None)
libc.malloc.restype = ctypes.c_void_p
libc.malloc.argtypes = [ctypes.c_size_t]
libc.free.argtypes = [ctypes.c_void_p]


def f():
    buf = ctypes.create_string_buffer(8)
    libc.free(ctypes.addressof(buf))

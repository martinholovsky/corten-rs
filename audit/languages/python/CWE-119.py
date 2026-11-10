# @compiles: hatch
# CWE-119: a loop writes one element past a ctypes array through memset.
import ctypes


def f():
    a = (ctypes.c_int * 4)()
    for i in range(5):
        ctypes.memset(ctypes.addressof(a) + 4 * i, 0, 4)

# @compiles: hatch
# CWE-786: an address is moved below a buffer's start and written.
import ctypes


def f(buf):
    ctypes.memset(ctypes.addressof(buf) - 1, 0, 1)

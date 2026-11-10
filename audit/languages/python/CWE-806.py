# @compiles: hatch
# CWE-806: a copy uses the source's size for a smaller destination.
import ctypes


def f(src):
    small = ctypes.create_string_buffer(4)
    ctypes.memmove(small, src, ctypes.sizeof(src))

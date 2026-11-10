# @compiles: hatch
# CWE-124: a write lands before the start of a buffer.
import ctypes


def f(i: int):
    buf = ctypes.create_string_buffer(8)
    ctypes.memset(ctypes.addressof(buf) + i - 8, 0, 1)

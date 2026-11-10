# @compiles: hatch
# CWE-127: a read lands before the start of a buffer.
import ctypes


def f(off: int) -> bytes:
    buf = ctypes.create_string_buffer(8)
    return ctypes.string_at(ctypes.addressof(buf) - off, 1)

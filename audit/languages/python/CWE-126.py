# @compiles: hatch
# CWE-126: string_at reads past the end of a buffer.
import ctypes


def f() -> bytes:
    buf = ctypes.create_string_buffer(8)
    return ctypes.string_at(buf, 64)

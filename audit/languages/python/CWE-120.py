# @compiles: hatch
# CWE-120: input is copied into a 16-byte buffer without a length check.
import ctypes


def f(data: bytes):
    buf = ctypes.create_string_buffer(16)
    ctypes.memmove(buf, data, len(data))

# @compiles: hatch
# CWE-242: libc's gets is called through ctypes.
import ctypes


def f():
    buf = ctypes.create_string_buffer(64)
    ctypes.CDLL(None).gets(buf)

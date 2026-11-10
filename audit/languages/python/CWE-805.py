# @compiles: hatch
# CWE-805: memmove is given a length unrelated to the destination.
import ctypes


def f(src: bytes, n: int):
    dst = ctypes.create_string_buffer(8)
    ctypes.memmove(dst, src, n)

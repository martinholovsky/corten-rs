# @compiles: hatch
# CWE-785: libc's realpath is given a buffer smaller than PATH_MAX.
import ctypes


def f(path: bytes):
    out = ctypes.create_string_buffer(64)
    ctypes.CDLL(None).realpath(path, out)

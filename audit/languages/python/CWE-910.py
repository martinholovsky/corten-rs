# @compiles
# CWE-910: a file's descriptor is closed behind its back and the number is reused.
import os


def f(a):
    os.close(a.fileno())
    b = open("/etc/hostname", "rb")
    return a.read(8), b

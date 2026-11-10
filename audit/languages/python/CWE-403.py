# @compiles
# CWE-403: a descriptor is made inheritable before a child is started.
import os
import subprocess


def f(path: str):
    fd = os.open(path, os.O_RDONLY)
    os.set_inheritable(fd, True)
    subprocess.run(["cat"], close_fds=False)

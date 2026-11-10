# @compiles
# CWE-828: the handler does buffered I/O that is not safe to re-enter.
import signal
import sys


def handler(signum, frame):
    sys.stdout.write("bye\n")
    sys.stdout.flush()


signal.signal(signal.SIGTERM, handler)

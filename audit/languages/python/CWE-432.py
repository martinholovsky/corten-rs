# @compiles
# CWE-432: the handler stays installed while shared state is half-updated.
import signal

a = b = 0


def handler(signum, frame):
    print(a, b)


signal.signal(signal.SIGINT, handler)
a = 1
b = 1

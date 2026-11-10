# @compiles
# CWE-479: the handler calls print, which is not reentrant if the main code is inside print.
import signal


def handler(signum, frame):
    print("signal", signum)


signal.signal(signal.SIGINT, handler)

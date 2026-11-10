# @compiles
# CWE-364: the handler clears state the interrupted code is still using.
import signal

buf = bytearray(64)


def handler(signum, frame):
    global buf
    buf = None


signal.signal(signal.SIGTERM, handler)
buf[0] = 1

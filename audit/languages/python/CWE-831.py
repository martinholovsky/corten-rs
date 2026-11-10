# @compiles
# CWE-831: one handler serves two signals and keeps shared state.
import signal

log = []


def handler(signum, frame):
    log.append(signum)


signal.signal(signal.SIGHUP, handler)
signal.signal(signal.SIGTERM, handler)

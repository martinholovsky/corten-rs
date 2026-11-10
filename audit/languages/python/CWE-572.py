# @compiles
# CWE-572: Thread.run() runs the target on the calling thread; start() was meant.
import threading


def f(task):
    threading.Thread(target=task).run()

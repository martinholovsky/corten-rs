# @compiles
# CWE-567: two threads increment an unsynchronised global.
import threading

counter = 0


def work():
    global counter
    for _ in range(100000):
        counter += 1


threads = [threading.Thread(target=work) for _ in range(2)]

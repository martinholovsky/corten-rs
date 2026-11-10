# @compiles
# CWE-1070: a picklable object holds a lambda, which pickle rejects at run time.
import pickle


class Job:
    def __init__(self):
        self.callback = lambda: None


def save(j: Job) -> bytes:
    return pickle.dumps(j)

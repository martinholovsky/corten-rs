# @compiles
# CWE-502: pickle.loads on untrusted bytes runs whatever __reduce__ names.
import pickle


def load(data: bytes):
    return pickle.loads(data)

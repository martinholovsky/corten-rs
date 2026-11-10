# @compiles
# CWE-499: pickle serialises every attribute, the password included.
import pickle


class Session:
    def __init__(self, user: str, password: str):
        self.user = user
        self.password = password


def save(s: Session) -> bytes:
    return pickle.dumps(s)

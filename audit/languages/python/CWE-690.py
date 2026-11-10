# @compiles
# CWE-690: dict.get returns None, which is used unchecked.
def f(users: dict) -> str:
    return users.get("admin").name

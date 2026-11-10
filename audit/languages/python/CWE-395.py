# @compiles
# CWE-395: AttributeError is caught to detect a None.
def name(user) -> str:
    try:
        return user.name
    except AttributeError:
        return "anonymous"

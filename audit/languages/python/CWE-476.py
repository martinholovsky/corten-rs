# @compiles
# CWE-476: an attribute is read through a value that may be None.
def name(user) -> str:
    return user.name


name(None)

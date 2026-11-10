# @compiles
# CWE-914: input names the attribute that setattr writes.
class Account:
    role = "user"


def set_field(a: Account, field: str, value):
    setattr(a, field, value)

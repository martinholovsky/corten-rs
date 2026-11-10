# @compiles
# CWE-584: a return in finally discards the exception (a SyntaxWarning since 3.14, still compiled).
def f() -> int:
    try:
        raise PermissionError("denied")
    finally:
        return 0

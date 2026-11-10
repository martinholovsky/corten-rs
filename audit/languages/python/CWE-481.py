# @compiles
# CWE-481: an assignment expression in a condition assigns instead of comparing.
def f(role: int) -> bool:
    if role := 0:
        return True
    return False

# @compiles
# CWE-456: an attribute left at None is trusted.
class Session:
    def __init__(self, user: str):
        self.user = user
        self.role = None

    def is_admin(self) -> bool:
        return self.role.startswith("admin")

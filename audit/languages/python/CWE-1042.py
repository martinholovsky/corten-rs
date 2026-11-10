# @compiles
# CWE-1042: a class attribute shared by every instance holds per-user state.
class Session:
    current_user = None

    def login(self, uid):
        Session.current_user = uid

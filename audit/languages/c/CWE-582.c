// @compiles
// CWE-582: the pointer is const, the array it names is not.
static int admin_ids[] = {1, 2, 3};
int *const ADMINS = admin_ids;

void tamper(void) {
    ADMINS[0] = 999;
}

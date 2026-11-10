// @compiles
// CWE-1055: a class inherits from two concrete classes.
struct Logger { int level = 0; void log() {} };
struct Store { int size = 0; void save() {} };
struct Service : Logger, Store { };

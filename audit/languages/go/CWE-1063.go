// @compiles
// CWE-1063: an init function creates the package's instance at load.
package p

type store struct{ items map[string]string }

var instance *store

func init() {
	instance = &store{items: map[string]string{}}
}

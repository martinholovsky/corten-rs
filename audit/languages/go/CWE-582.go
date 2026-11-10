// @compiles
// CWE-582: an exported package-level slice is writable by any importer.
package p

var AdminIDs = []int{1, 2, 3}

func tamper() {
	AdminIDs[0] = 999
}

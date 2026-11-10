// @compiles
// CWE-685: Printf is given fewer arguments than its format consumes.
package p

import (
	"fmt"
)

func f(x int) string {
	return fmt.Sprintf("%d %d", x)
}

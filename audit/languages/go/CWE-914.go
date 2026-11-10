// @compiles
// CWE-914: input names the struct field that reflection writes.
package p

import (
	"reflect"
)

type account struct{ Role string }

func set(a *account, field, value string) {
	reflect.ValueOf(a).Elem().FieldByName(field).SetString(value)
}

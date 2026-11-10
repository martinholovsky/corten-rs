// @compiles
// CWE-470: input names the method that is called.
package p

import (
	"reflect"
)

type handler struct{}

func (handler) Status() string { return "ok" }

func call(name string) []reflect.Value {
	return reflect.ValueOf(handler{}).MethodByName(name).Call(nil)
}

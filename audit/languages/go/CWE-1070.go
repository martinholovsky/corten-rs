// @compiles
// CWE-1070: a struct to be marshalled contains a channel, which encoding/json rejects at run time.
package p

import (
	"encoding/json"
)

type event struct {
	Name string
	Done chan bool
}

func encode(e event) ([]byte, error) {
	return json.Marshal(e)
}

// @compiles
// CWE-499: encoding/json marshals the exported Password field.
package p

import (
	"encoding/json"
)

type Session struct {
	User     string
	Password string
}

func save(s Session) ([]byte, error) {
	return json.Marshal(s)
}

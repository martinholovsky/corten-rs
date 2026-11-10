// @rejected: syntax error: unexpected name A after top level declaration
// CWE-1055: Go has no class inheritance; a type cannot extend two concrete types.
package p

type A struct{ n int }
type B struct{ m int }
type C extends A, B {}

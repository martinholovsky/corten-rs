// @compiles
// CWE-567: two goroutines increment an unsynchronised variable.
package p

import (
	"sync"
)

var counter int

func f() {
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 1000 {
				counter++
			}
		}()
	}
	wg.Wait()
}

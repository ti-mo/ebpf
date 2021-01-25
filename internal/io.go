package internal

import (
	"fmt"
)

// DiscardZeroes makes sure that all written bytes are zero
// before discarding them.
type DiscardZeroes struct{}

func (DiscardZeroes) Write(p []byte) (int, error) {
	for _, b := range p {
		if b != 0 {
			return 0, fmt.Errorf("encountered non-zero byte in slice %v", p)
		}
	}
	return len(p), nil
}

package processing

import (
	"slices"
	"strings"

	"github.com/drduh/mess/internal/tally"
)

type Count = tally.Count

// sortNodes orders nodes by total activity, ties by name.
func sortNodes(nodes []*Node) {
	slices.SortFunc(nodes, func(a, b *Node) int {
		at, bt := a.AsCaller+a.AsImage, b.AsCaller+b.AsImage
		if at != bt {
			return bt - at
		}

		return strings.Compare(a.Name, b.Name)
	})
}

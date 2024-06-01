package dns

import (
	"strings"
)

func splitNameIntoLabels(name string) []string {
	components := strings.Split(name, ".")
	for len(components) > 0 && len(components[len(components)-1]) == 0 {
		components = components[:len(components)-1]
	}
	return components
}

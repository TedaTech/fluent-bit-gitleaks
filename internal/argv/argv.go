package argv

import "os"

func init() {
	if len(os.Args) == 0 {
		os.Args = []string{"fluent-bit-gitleaks"}
	}
}

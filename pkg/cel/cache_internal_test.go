package cel

import (
	"fmt"
	"testing"
)

func TestEnvironmentCacheKeepsWorkingSet(t *testing.T) {
	const count = 64
	libs := make([]*CustomLib, count)
	for i := range libs {
		lib := NewCustomLib()
		lib.PreRegisterRuleFunctions([]string{fmt.Sprintf("cached_rule_%d", i)})
		if _, err := lib.getEnv(); err != nil {
			t.Fatal(err)
		}
		libs[i] = lib
	}
	for i, original := range libs {
		lib := NewCustomLib()
		lib.PreRegisterRuleFunctions([]string{fmt.Sprintf("cached_rule_%d", i)})
		env, err := lib.getEnv()
		if err != nil {
			t.Fatal(err)
		}
		if env != original.env {
			t.Fatalf("环境 %d 在工作集未满时被淘汰", i)
		}
	}
}

package arborist

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncodeDecode(t *testing.T) {
	inputs := []string{
		"test",
		"!@#$%^&*()`\\=+-_'\"<>?,.",
		"___ooOO00O___",
		"foo-=-bar-=-baz",
		"🙃",
	}

	var regValidDbPath *regexp.Regexp = regexp.MustCompile(`^[a-zA-Z0-9_]+$`)

	for _, input := range inputs {
		encoded := UnderscoreEncode(input)
		assert.Equal(t, input, UnderscoreDecode(encoded), "encode/decode broken")
		assert.True(t, regValidDbPath.MatchString(encoded), "encoded contains invalid characters")
	}
}

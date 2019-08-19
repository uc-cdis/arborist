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
		"_-.~",
		"___ooOO00O___",
		"foo-=-bar-=-baz",
		"__S0_S1___S2_S3_S4_S5_S6_S7_2F__2F____AB",
		"🙃",
	}

	var regValidDbPath *regexp.Regexp = regexp.MustCompile(`^[a-zA-Z0-9_]+$`)

	for _, input := range inputs {
		encoded := UnderscoreEncode(input)
		assert.Equal(t, input, UnderscoreDecode(encoded), "encode/decode broken")
		assert.True(t, regValidDbPath.MatchString(encoded), "encoded contains invalid characters")
	}
}

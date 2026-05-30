package abuse

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReporter_Check(t *testing.T) {
	r := NewReporter()
	res, err := r.Check("8.8.8.8")
	require.NoError(t, err)
	assert.NotNil(t, res)
	assert.GreaterOrEqual(t, res.Score, 0)
	assert.LessOrEqual(t, res.Score, 100)
}

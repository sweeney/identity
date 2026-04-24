package admin

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestQRSVG_EncodesData(t *testing.T) {
	got, err := qrSVG("https://id.example.com/device?code=ABCD-1234-EFGH", 200)
	require.NoError(t, err)

	s := string(got)
	assert.True(t, strings.HasPrefix(s, "<svg "), "should start with svg tag")
	assert.Contains(t, s, `width="200"`)
	assert.Contains(t, s, `height="200"`)
	assert.Contains(t, s, `viewBox="0 0`)
	assert.Contains(t, s, `<rect `, "should contain at least one black module")
	assert.True(t, strings.HasSuffix(s, "</svg>"), "should end with closing svg tag")
}

func TestQRSVG_EmptyData(t *testing.T) {
	_, err := qrSVG("", 200)
	assert.Error(t, err)
}

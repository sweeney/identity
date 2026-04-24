package admin

import (
	"fmt"
	"html/template"
	"strings"

	"rsc.io/qr"
)

// qrSVG returns an inline SVG representation of the QR code for data. The
// caller is expected to pass the result straight into a template via the
// html/template safe-HTML escape hatch — callers inside this package already
// do that.
//
// The SVG has a width/height of sizePx pixels. The matrix itself is unitless
// (1×1 per module) and scales to fit via viewBox, so the stickers are crisp
// at any size when printed.
func qrSVG(data string, sizePx int) (template.HTML, error) {
	if data == "" {
		return "", fmt.Errorf("qr: empty data")
	}
	code, err := qr.Encode(data, qr.M)
	if err != nil {
		return "", fmt.Errorf("qr encode: %w", err)
	}

	modules := code.Size
	var sb strings.Builder
	fmt.Fprintf(&sb,
		`<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d" shape-rendering="crispEdges" aria-label="QR code"><rect width="%d" height="%d" fill="#ffffff"/>`,
		sizePx, sizePx, modules, modules, modules, modules,
	)
	// Emit one <rect> per black module. We coalesce horizontal runs into a
	// single rect to keep the SVG small.
	for y := 0; y < modules; y++ {
		x := 0
		for x < modules {
			if !code.Black(x, y) {
				x++
				continue
			}
			start := x
			for x < modules && code.Black(x, y) {
				x++
			}
			fmt.Fprintf(&sb, `<rect x="%d" y="%d" width="%d" height="1" fill="#000000"/>`, start, y, x-start)
		}
	}
	sb.WriteString(`</svg>`)
	return template.HTML(sb.String()), nil //nolint:gosec // generated content is SVG we built from sanitized ints.
}

package util

import "fmt"

// ANSI color codes
var (
	ColorReset = "\033[0m"
	ColorGrey  = "\033[90m"
	ColorGreen = "\033[32m"
	ColorRed   = "\033[31m"
)

// Colorizef formats a string with the given color and resets the color afterwards
func Colorizef(color string, format string, a ...any) string {
	return fmt.Sprintf("%s%s%s", color, fmt.Sprintf(format, a...), ColorReset)
}

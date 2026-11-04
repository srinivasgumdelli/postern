//go:build race

package scan

// The race detector slows regex-heavy code roughly 10-20x.
const raceFactor = 20

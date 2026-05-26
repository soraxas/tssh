/*
MIT License

Copyright (c) 2024-2026 The Trzsz SSH Authors.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

package tsshd

import (
	"bytes"
	"fmt"
)

func extractTmuxOutputPrefix(cacheLines [][]byte) string {
	tmuxOutputCount := 0
	for _, line := range cacheLines {
		if len(line) == 0 || line[0] != '%' {
			continue
		}
		var idx int
		if bytes.HasPrefix(line, []byte("%output %")) {
			idx = 8
		} else if bytes.HasPrefix(line, []byte("%extended-output %")) {
			idx = 17
		}
		if idx > 0 {
			tmuxOutputCount++
			// In tmux Control Mode, a large number of output messages are expected.
			// Extract the pane ID once enough output lines are observed.
			if tmuxOutputCount >= min(10, maxPendingOutputLines) {
				rest := line[idx:]
				if pos := bytes.IndexByte(rest, ' '); pos > 0 {
					return "%output " + string(rest[:pos+1])
				}
			}
		}
	}
	return ""
}

func encodeTmuxOutput(prefix string, output []byte) []byte {
	buffer := bytes.NewBuffer(make([]byte, 0, len(prefix)+len(output)<<2+2))
	buffer.Write([]byte(prefix))
	for _, b := range output {
		if b < ' ' || b == '\\' || b > '~' {
			fmt.Fprintf(buffer, "\\%03o", b)
		} else {
			buffer.WriteByte(b)
		}
	}
	buffer.Write([]byte("\r\n"))
	return buffer.Bytes()
}

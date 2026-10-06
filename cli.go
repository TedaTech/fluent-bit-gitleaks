//go:build !wasip1

package main

import (
	"bufio"
	"log"
	"os"
)

func main() {
	s, err := NewScrubber()
	if err != nil {
		log.Fatal(err)
	}
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 1<<20)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for in.Scan() {
		out.Write(s.Scrub(in.Bytes()))
		out.WriteByte('\n')
	}
}

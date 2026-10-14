//go:build !wasip1

package main

import (
	"bufio"
	"log"
	"os"
)

func main() {
	tag := "kube.cli"
	if len(os.Args) > 1 {
		tag = os.Args[1]
	}
	s, err := NewScrubber()
	if err != nil {
		log.Fatal(err)
	}
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 1<<20)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for in.Scan() {
		out.Write(s.Scrub(tag, in.Bytes()))
		out.WriteByte('\n')
	}
}

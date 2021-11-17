package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

type config struct {
	forwardaddr string
	listenaddr  string
}

func configFromFile(name string) (config, error) {
	f, err := os.Open(name)
	if err != nil {
		return config{}, err
	}
	defer f.Close()
	return parseConfig(f)
}

func parseConfig(r io.Reader) (config, error) {
	sc := bufio.NewScanner(r)
	var c config
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "#") {
			continue // skip config comments
		}
		fields := strings.Fields(line)
		if len(fields) > 2 {
			return c, fmt.Errorf("too many values for key %s", fields[0])
		}
		switch k := fields[0]; k {
		case "listen":
			c.listenaddr = fields[1]
		case "forward":
			c.forwardaddr = fields[1]
		default:
			return c, fmt.Errorf("unknown key %s", k)
		}
	}
	return c, nil
}

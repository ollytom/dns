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
	usetls      bool
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
		switch k := fields[0]; k {
		case "listen":
			if len(fields) < 2 {
				return c, fmt.Errorf("missing value for key %s", k)
			} else if len(fields) > 2 {
				return c, fmt.Errorf("too many values for key %s", k)
			}
			c.listenaddr = fields[1]
		case "forward":
			if len(fields) < 2 {
				return c, fmt.Errorf("missing value for key %s", k)
			} else if len(fields) > 3 {
				return c, fmt.Errorf("too many values for key %s", k)
			}
			c.forwardaddr = fields[1]
			if len(fields) == 3 {
				if fields[2] == "tls" {
					c.usetls = true
				} else {
					return c, fmt.Errorf("invalid tls option in forward")
				}
			}
		default:
			return c, fmt.Errorf("unknown key %s", k)
		}
	}
	return c, nil
}

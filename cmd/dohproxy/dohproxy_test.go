package main

import (
	"strings"
	"testing"
)

func TestGoodConfig(t *testing.T) {
	b := `# a comment
listen syd.olowe.co
forward 9.9.9.9:domain`
	r := strings.NewReader(b)
	config, err := parseConfig(r)
	if err != nil {
		t.Log(config)
		t.Error(err)
	}
	b2 := `# a comment
listen syd.olowe.co
forward 9.9.9.9:853 tls`
	r = strings.NewReader(b2)
	config, err = parseConfig(r)
	if err != nil {
		t.Log(config)
		t.Error(err)
	}
}

func TestBadConfig(t *testing.T) {
	b := `asdfasdfuwoefksd`
	r := strings.NewReader(b)
	config, err := parseConfig(r)
	if err == nil {
		t.Log(config)
		t.Error(err)
	}
	b2 := `# a comment
listen syd.olowe.co
forward 9.9.9.9:853 badoption`
	r = strings.NewReader(b2)
	config, err = parseConfig(r)
	if err == nil {
		t.Log(config)
		t.Error(err)
	}
}

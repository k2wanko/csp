package csp

import (
	"testing"
)

func TestSourcesString(t *testing.T) {
	s := Sources{"'self'", "*.trusted.com"}
	if s, want := s.String(), "'self' *.trusted.com"; s != want {
		t.Errorf("s = %s; want %s", s, want)
	}
}

func TestDirectiveString(t *testing.T) {
	d := &Directive{
		Type:    DefaultSrc,
		Sources: Sources{"'self'", "*.trusted.com"},
	}

	if d, want := d.String(), "default-src 'self' *.trusted.com"; d != want {
		t.Errorf("d = %s; want %s", d, want)
	}
}

func TestSingleDirective(t *testing.T) {
	d := &Directive{
		Type: BlockAllMixedContent,
	}

	if d, want := d.String(), "block-all-mixed-content"; d != want {
		t.Errorf("d = %s; want %v", d, want)
	}
}

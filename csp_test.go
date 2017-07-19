package csp

import (
	"net/http/httptest"
	"testing"
)

func TestCSPReportOnlyHeader(t *testing.T) {
	c := &CSP{
		ReportOnly: true,
		DefaultSrc: Sources{"'self'"},
	}
	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	c.ServeHTTP(w, r)

	policy := w.Header().Get("Content-Security-Policy-Report-Only")
	if policy == "" {
		t.Error("policy is empty")
	}
}

func TestCSPSimplePolicy(t *testing.T) {
	c := &CSP{
		DefaultSrc: Sources{"'self'"},
	}

	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	c.ServeHTTP(w, r)

	policy := w.Header().Get("Content-Security-Policy")
	if policy == "" {
		t.Error("policy is empty")
	}

	if want := "default-src 'self'"; policy != want {
		t.Errorf("policy = %s; want = %v", policy, want)
	}
}

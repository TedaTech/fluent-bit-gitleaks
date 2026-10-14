package main

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"
)

var (
	s3Secret  = "Zk3r9QpL" + "2mN8vX4tY7wB1cD5eF6g"
	awsKey    = "AKIA" + "Z7QW3RT5YUXIOP2L"
	apiSecret = "q8Rf2LxW" + "9mTz4KcVb7NpYs3H"
)

func TestScrub(t *testing.T) {
	s := scrubber(t)
	cases := []struct {
		name, log, secret, rule string
	}{
		{"linstor raw", `remote s3 secrets:{key:"secret-key" value:"` + s3Secret + `"}`, s3Secret, "kv-pair-secret"},
		{"linstor escaped", `"msg":"remote secrets:{key:\"secret-key\" value:\"` + s3Secret + `\"}"`, s3Secret, "kv-pair-secret"},
		{"generic api key", `connecting with api_key=` + apiSecret, apiSecret, "generic-api-key"},
		{"aws access key", `using credentials ` + awsKey, awsKey, "aws-access-token"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := scrubLog(t, s, c.log)
			if strings.Contains(out, c.secret) {
				t.Fatalf("secret survived: %s", out)
			}
			if !strings.Contains(out, "REDACTED:"+c.rule) {
				t.Fatalf("want REDACTED:%s, got %s", c.rule, out)
			}
		})
	}
}

func TestScrubKeepsNonSecrets(t *testing.T) {
	s := scrubber(t)
	for name, line := range map[string]string{
		"allowlisted example key": "docs say AKIAIOSFODNN7EXAMPLE",
		"below entropy":           "password=aaaaaaaaaaaaaaaa",
		"plain line":              "GET /healthz 200 1ms",
	} {
		t.Run(name, func(t *testing.T) {
			if out := scrubLog(t, s, line); out != line {
				t.Fatalf("changed: %s", out)
			}
		})
	}
}

func TestScrubNested(t *testing.T) {
	s := scrubber(t)
	in := `{"kubernetes":{"labels":{"x":"api_key=` + apiSecret + `"}},"n":3,"a":["token=` + apiSecret + `"]}`
	out := string(s.Scrub("kube.test", []byte(in)))
	if strings.Contains(out, apiSecret) {
		t.Fatalf("secret survived: %s", out)
	}
	if !strings.Contains(out, `"n":3`) {
		t.Fatalf("number changed: %s", out)
	}
}

func TestScrubFailsClosed(t *testing.T) {
	s := scrubber(t)
	if out := string(s.Scrub("kube.test", []byte(`{"log":"api_key=` + apiSecret))); out != string(scrubErrorRecord) {
		t.Fatalf("got %s", out)
	}
}

func TestScrubPII(t *testing.T) {
	s := scrubber(t)
	cases := []struct {
		name, tag, log, pii, rule string
	}{
		{"email in container log", "kube.var.log.containers", "user fgruntjes@tedatech.app logged in", "fgruntjes@tedatech.app", "pii-email"},
		{"public ip in container log", "kube.var.log.containers", "request from 83.84.1.17 denied", "83.84.1.17", "pii-ipv4"},
		{"public ip in event", "events.0", "connection refused from 203.0.114.9", "203.0.114.9", "pii-ipv4"},
		{"first public 172", "kube.test", "peer 172.32.0.1 timed out", "172.32.0.1", "pii-ipv4"},
		{"four-part version masked by design", "kube.test", "running build 8.30.1.7", "8.30.1.7", "pii-ipv4"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := scrubTagged(t, s, c.tag, c.log)
			if strings.Contains(out, c.pii) {
				t.Fatalf("pii survived: %s", out)
			}
			if !strings.Contains(out, "REDACTED:"+c.rule) {
				t.Fatalf("want REDACTED:%s, got %s", c.rule, out)
			}
		})
	}
}

func TestScrubPIIKeepsPrivateRanges(t *testing.T) {
	s := scrubber(t)
	for _, ip := range []string{"10.0.7.136", "127.0.0.1", "169.254.1.1", "192.168.1.1", "172.16.0.1", "172.31.255.255", "0.0.0.0"} {
		t.Run(ip, func(t *testing.T) {
			line := "dialing " + ip + ":8080"
			if out := scrubTagged(t, s, "kube.test", line); out != line {
				t.Fatalf("changed: %s", out)
			}
		})
	}
}

func TestScrubPIIKeepsNonPII(t *testing.T) {
	s := scrubber(t)
	for name, line := range map[string]string{
		"semver":    "fluent-bit 5.1.3 started",
		"plain":     "GET /healthz 200 1ms",
		"at symbol": "job ran at 12:00",
	} {
		t.Run(name, func(t *testing.T) {
			if out := scrubTagged(t, s, "kube.test", line); out != line {
				t.Fatalf("changed: %s", out)
			}
		})
	}
}

func TestScrubPIITagScope(t *testing.T) {
	s := scrubber(t)
	for _, tag := range []string{"node.kernel", "node.etcd", "audit.var.log"} {
		t.Run(tag+" keeps pii", func(t *testing.T) {
			line := "peer 83.84.1.17 user fgruntjes@tedatech.app"
			if out := scrubTagged(t, s, tag, line); out != line {
				t.Fatalf("changed: %s", out)
			}
		})
		t.Run(tag+" still scrubs secrets", func(t *testing.T) {
			out := scrubTagged(t, s, tag, "connecting with api_key="+apiSecret)
			if strings.Contains(out, apiSecret) {
				t.Fatalf("secret survived: %s", out)
			}
		})
	}
}

func TestScrubPIINestedArray(t *testing.T) {
	s := scrubber(t)
	in := `{"user":{"username":"x"},"sourceIPs":["83.84.1.17","10.0.0.9"],"n":3}`
	out := string(s.Scrub("events.0", []byte(in)))
	if strings.Contains(out, "83.84.1.17") || !strings.Contains(out, "10.0.0.9") || !strings.Contains(out, `"n":3`) {
		t.Fatalf("got %s", out)
	}
}

func scrubLog(t *testing.T, s *Scrubber, line string) string {
	return scrubTagged(t, s, "kube.test", line)
}

func scrubTagged(t *testing.T, s *Scrubber, tag, line string) string {
	t.Helper()
	in, _ := json.Marshal(map[string]string{"log": line})
	var out map[string]string
	if err := json.Unmarshal(s.Scrub(tag, in), &out); err != nil {
		t.Fatal(err)
	}
	return out["log"]
}

var shared = sync.OnceValues(NewScrubber)

func scrubber(t *testing.T) *Scrubber {
	t.Helper()
	s, err := shared()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestScrubUsesFieldNameAsContext(t *testing.T) {
	s := scrubber(t)
	out := string(s.Scrub("kube.test", []byte(`{"api_key":"`+apiSecret+`","msg":"login ok"}`)))
	if strings.Contains(out, apiSecret) || !strings.Contains(out, `"api_key":"REDACTED:generic-api-key"`) {
		t.Fatalf("got %s", out)
	}
}

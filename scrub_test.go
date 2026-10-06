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
	out := string(s.Scrub([]byte(in)))
	if strings.Contains(out, apiSecret) {
		t.Fatalf("secret survived: %s", out)
	}
	if !strings.Contains(out, `"n":3`) {
		t.Fatalf("number changed: %s", out)
	}
}

func TestScrubFailsClosed(t *testing.T) {
	s := scrubber(t)
	if out := string(s.Scrub([]byte(`{"log":"api_key=` + apiSecret))); out != string(scrubErrorRecord) {
		t.Fatalf("got %s", out)
	}
}

func scrubLog(t *testing.T, s *Scrubber, line string) string {
	t.Helper()
	in, _ := json.Marshal(map[string]string{"log": line})
	var out map[string]string
	if err := json.Unmarshal(s.Scrub(in), &out); err != nil {
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
	out := string(s.Scrub([]byte(`{"api_key":"` + apiSecret + `","msg":"login ok"}`)))
	if strings.Contains(out, apiSecret) || !strings.Contains(out, `"api_key":"REDACTED:generic-api-key"`) {
		t.Fatalf("got %s", out)
	}
}

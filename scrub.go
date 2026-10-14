package main

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"regexp"
	"strings"

	"github.com/spf13/viper"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
)

//go:embed gitleaks.toml
var rules string

var scrubErrorRecord = []byte(`{"log":"REDACTED:scrub-error"}`)

// pii-* rules apply only to tenant-facing records; node and audit logs keep
// their addresses (infra debugging, security forensics).
var piiTags = regexp.MustCompile(`^(kube|events)(\.|$)`)

type Scrubber struct {
	d *detect.Detector
}

func NewScrubber() (*Scrubber, error) {
	v := viper.New()
	v.SetConfigType("toml")
	if err := v.ReadConfig(strings.NewReader(rules)); err != nil {
		return nil, err
	}
	var vc config.ViperConfig
	if err := v.Unmarshal(&vc); err != nil {
		return nil, err
	}
	cfg, err := vc.Translate()
	if err != nil {
		return nil, err
	}
	return &Scrubber{d: detect.NewDetector(cfg)}, nil
}

func (s *Scrubber) Scrub(tag string, record []byte) []byte {
	dec := json.NewDecoder(bytes.NewReader(record))
	dec.UseNumber()
	var body map[string]any
	if err := dec.Decode(&body); err != nil {
		return scrubErrorRecord
	}
	if !s.walk(tag, body) {
		return record
	}
	out, err := json.Marshal(body)
	if err != nil {
		return scrubErrorRecord
	}
	return out
}

func (s *Scrubber) walk(tag string, v any) bool {
	changed := false
	switch t := v.(type) {
	case map[string]any:
		for k, e := range t {
			if r, ok := s.visit(tag, k+"=", e); ok {
				t[k], changed = r, true
			}
		}
	case []any:
		for i, e := range t {
			if r, ok := s.visit(tag, "", e); ok {
				t[i], changed = r, true
			}
		}
	}
	return changed
}

func (s *Scrubber) visit(tag, context string, e any) (any, bool) {
	if str, ok := e.(string); ok {
		return s.redact(tag, context, str)
	}
	return e, s.walk(tag, e)
}

func (s *Scrubber) redact(tag, context, str string) (string, bool) {
	findings := s.d.DetectString(context + str)
	if len(findings) == 0 {
		return str, false
	}
	changed := false
	for _, f := range findings {
		if f.Secret == "" {
			continue
		}
		if strings.HasPrefix(f.RuleID, "pii-") && !piiTags.MatchString(tag) {
			continue
		}
		str = strings.ReplaceAll(str, f.Secret, "REDACTED:"+f.RuleID)
		changed = true
	}
	return str, changed
}

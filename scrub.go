package main

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"strings"

	"github.com/spf13/viper"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
)

//go:embed gitleaks.toml
var rules string

var scrubErrorRecord = []byte(`{"log":"REDACTED:scrub-error"}`)

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

func (s *Scrubber) Scrub(record []byte) []byte {
	dec := json.NewDecoder(bytes.NewReader(record))
	dec.UseNumber()
	var body map[string]any
	if err := dec.Decode(&body); err != nil {
		return scrubErrorRecord
	}
	if !s.walk(body) {
		return record
	}
	out, err := json.Marshal(body)
	if err != nil {
		return scrubErrorRecord
	}
	return out
}

func (s *Scrubber) walk(v any) bool {
	changed := false
	switch t := v.(type) {
	case map[string]any:
		for k, e := range t {
			if r, ok := s.visit(k+"=", e); ok {
				t[k], changed = r, true
			}
		}
	case []any:
		for i, e := range t {
			if r, ok := s.visit("", e); ok {
				t[i], changed = r, true
			}
		}
	}
	return changed
}

func (s *Scrubber) visit(context string, e any) (any, bool) {
	if str, ok := e.(string); ok {
		return s.redact(context, str)
	}
	return e, s.walk(e)
}

func (s *Scrubber) redact(context, str string) (string, bool) {
	findings := s.d.DetectString(context + str)
	if len(findings) == 0 {
		return str, false
	}
	for _, f := range findings {
		if f.Secret != "" {
			str = strings.ReplaceAll(str, f.Secret, "REDACTED:"+f.RuleID)
		}
	}
	return str, true
}

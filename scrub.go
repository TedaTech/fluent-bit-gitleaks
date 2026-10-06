package main

import (
	_ "embed"
	"bytes"
	"encoding/json"
	"strings"

	"github.com/spf13/viper"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
)

//go:embed gitleaks.toml
var rules string

var stub = []byte(`{"log":"REDACTED:scrub-error"}`)

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
		return stub
	}
	if !s.walk(body) {
		return record
	}
	out, err := json.Marshal(body)
	if err != nil {
		return stub
	}
	return out
}

func (s *Scrubber) walk(v any) bool {
	changed := false
	switch t := v.(type) {
	case map[string]any:
		for k, e := range t {
			if str, ok := e.(string); ok {
				if r, ok := s.redact(str); ok {
					t[k], changed = r, true
				}
			} else if s.walk(e) {
				changed = true
			}
		}
	case []any:
		for i, e := range t {
			if str, ok := e.(string); ok {
				if r, ok := s.redact(str); ok {
					t[i], changed = r, true
				}
			} else if s.walk(e) {
				changed = true
			}
		}
	}
	return changed
}

func (s *Scrubber) redact(str string) (string, bool) {
	findings := s.d.DetectString(str)
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

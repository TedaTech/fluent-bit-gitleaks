package main

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"net/netip"
	"regexp"
	"strings"

	"github.com/hoophq/alcatraz/analyzer"
	"github.com/hoophq/alcatraz/anonymizer"
	"github.com/hoophq/alcatraz/entities"
	"github.com/hoophq/alcatraz/recognizers"
	"github.com/spf13/viper"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
)

//go:embed gitleaks.toml
var rules string

var scrubErrorRecord = []byte(`{"log":"REDACTED:scrub-error"}`)

// PII masking applies only to tenant-facing records; node and audit logs keep
// their addresses (infra debugging, security forensics).
var piiTags = regexp.MustCompile(`^(kube|events)(\.|$)`)

var piiOps = anonymizer.Config{PerEntity: map[string]anonymizer.Operator{
	entities.EmailAddress: anonymizer.ReplaceWith("REDACTED:pii-email"),
	entities.IPAddress: func(_, match string) string {
		if strings.Contains(match, ":") {
			return "REDACTED:pii-ipv6"
		}
		return "REDACTED:pii-ipv4"
	},
}}

type Scrubber struct {
	d   *detect.Detector
	pii *analyzer.Engine
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
	reg := analyzer.NewRegistry("en")
	reg.Add("en", recognizers.Email())
	reg.Add("en", recognizers.IP())
	return &Scrubber{
		d:   detect.NewDetector(cfg),
		pii: analyzer.NewEngine(reg, []string{"en"}),
	}, nil
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
	changed := false
	for _, f := range s.d.DetectString(context + str) {
		if f.Secret == "" {
			continue
		}
		str = strings.ReplaceAll(str, f.Secret, "REDACTED:"+f.RuleID)
		changed = true
	}
	if piiTags.MatchString(tag) {
		if out := s.redactPII(str); out != str {
			str, changed = out, true
		}
	}
	return str, changed
}

func (s *Scrubber) redactPII(str string) string {
	results := s.pii.Analyze(str, analyzer.Options{})
	kept := results[:0]
	for _, r := range results {
		if r.EntityType == entities.IPAddress {
			a, err := netip.ParseAddr(r.Text)
			if err != nil || !a.IsGlobalUnicast() || a.IsPrivate() {
				continue
			}
		}
		kept = append(kept, r)
	}
	if len(kept) == 0 {
		return str
	}
	return anonymizer.AnonymizeWith(str, kept, piiOps)
}

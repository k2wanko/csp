package csp

import (
	"net/http"
	"net/url"
	"strings"
)

const (
	Header           = "Content-Security-Policy"
	ReportOnlyHeader = "Content-Security-Policy-Report-Only"
)

type Level uint

const (
	Level1 Level = 1 << iota
	Level2
	Level3
)

var DefaultLevel Level = Level2

type CSP struct {
	Level      Level
	ReportOnly bool

	// directives

	BaseURI                Sources
	BlockAllMixedContent   bool
	ChildSrc               Sources
	ConnectSrc             Sources
	DefaultSrc             Sources
	FontSrc                Sources
	FormAction             Sources
	FrameAncestors         Sources
	FrameSrc               Sources
	ImgSrc                 Sources
	ManifestSrc            Sources
	MediaSrc               Sources
	ObjectSrc              Sources
	PluginTypes            Sources // TODO: plugin type/subtyp. https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/plugin-types
	Referrer               Sources
	ReportURI              *url.URL
	RequestSriFor          Sources
	Sandbox                Sources // TODO: sanbox values type. https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/sandbox
	ScriptSrc              Sources
	StyleSrc               Sources
	UpgradeInsecureRequest bool
	WorkerSrc              Sources
}

func (c *CSP) Policy() string {
	ds := map[DirectiveType]Sources{}

	if c.BlockAllMixedContent {
		ds[BlockAllMixedContent] = nil
	}

	if c.UpgradeInsecureRequest {
		ds[UpgradeInsecureRequest] = nil
	}

	cds := map[DirectiveType]Sources{
		BaseURI:       c.BaseURI,
		ChildSrc:      c.ChildSrc,
		ConnectSrc:    c.ConnectSrc,
		DefaultSrc:    c.DefaultSrc,
		FontSrc:       c.FontSrc,
		FormAction:    c.FormAction,
		FrameSrc:      c.FrameSrc,
		ImgSrc:        c.ImgSrc,
		ManifestSrc:   c.ManifestSrc,
		MediaSrc:      c.MediaSrc,
		ObjectSrc:     c.ObjectSrc,
		PluginTypes:   c.PluginTypes,
		Referrer:      c.Referrer,
		RequestSriFor: c.RequestSriFor,
		Sandbox:       c.Sandbox,
		ScriptSrc:     c.ScriptSrc,
		StyleSrc:      c.StyleSrc,
		WorkerSrc:     c.WorkerSrc,
	}
	for t, s := range cds {
		if s == nil {
			continue
		}
		ds[t] = s
	}

	lv := c.Level
	if lv == 0 {
		lv = DefaultLevel
	}

	if c.ReportURI != nil {
		if lv&Level2 != 0 {
			ds[ReportURI] = Sources{c.ReportURI.String()}
		}
		if lv&Level3 != 0 {
			ds[ReportTo] = Sources{c.ReportURI.String()}
		}
	}

	p := []string{}
	for t, s := range ds {
		d := &Directive{
			Type:    t,
			Sources: s,
		}
		p = append(p, d.String())
	}
	return strings.Join(p, "; ")
}

func (c *CSP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	hk := Header
	if c.ReportOnly {
		hk = ReportOnlyHeader
	}
	p := c.Policy()
	if p == "" {
		return
	}
	w.Header().Add(hk, p)
}

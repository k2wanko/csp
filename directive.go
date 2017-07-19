package csp

import (
	"strings"
)

type Sources []string

func (s Sources) String() string {
	if len(s) == 0 {
		return ""
	}

	return strings.Join([]string(s), " ")
}

type DirectiveType string

const (
	BaseURI                DirectiveType = "base-uri"
	BlockAllMixedContent   DirectiveType = "block-all-mixed-content"
	ChildSrc               DirectiveType = "child-src"
	ConnectSrc             DirectiveType = "connect-src"
	DefaultSrc             DirectiveType = "default-src"
	FontSrc                DirectiveType = "font-src"
	FormAction             DirectiveType = "form-action"
	FrameAncestors         DirectiveType = "frame-ancestors"
	FrameSrc               DirectiveType = "frame-src"
	ImgSrc                 DirectiveType = "img-src"
	ManifestSrc            DirectiveType = "manifest-src"
	MediaSrc               DirectiveType = "media-src"
	ObjectSrc              DirectiveType = "object-src"
	PluginTypes            DirectiveType = "plugin-types"
	Referrer               DirectiveType = "referrer"
	ReportTo               DirectiveType = "report-to"
	ReportURI              DirectiveType = "report-uri"
	RequestSriFor          DirectiveType = "require-sri-for"
	Sandbox                DirectiveType = "sandbox"
	ScriptSrc              DirectiveType = "script-src"
	StyleSrc               DirectiveType = "style-src"
	UpgradeInsecureRequest DirectiveType = "upgrade-insecure-requests"
	WorkerSrc              DirectiveType = "worker-src"
)

func (t DirectiveType) String() string {
	return string(t)
}

type Directive struct {
	Type    DirectiveType
	Sources Sources
}

func (d *Directive) String() string {
	if d == nil || d.Type == "" {
		return ""
	}

	return strings.Join(append([]string{d.Type.String()}, []string(d.Sources)...), " ")
}

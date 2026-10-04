package aidetect

// Optional pixel/signal-level classifiers. Metadata only proves AI when it is
// present; stripped files need a trained model, and we don't ship one. These
// adapters upload the file to a third-party API, so they are off unless
// explicitly enabled with -remote.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type Classifier interface {
	Name() string
	Supports(format string) bool
	Classify(ctx context.Context, path string) (score float64, detail string, err error)
}

var httpClient = &http.Client{Timeout: 3 * time.Minute}

func ParseClassifiers(names string) ([]Classifier, error) {
	var out []Classifier
	for _, n := range strings.Split(names, ",") {
		switch strings.TrimSpace(strings.ToLower(n)) {
		case "":
		case "hive":
			key := os.Getenv("HIVE_API_KEY")
			if key == "" {
				return nil, fmt.Errorf("hive: set HIVE_API_KEY")
			}
			out = append(out, hive{key: key})
		case "sightengine":
			u, s := os.Getenv("SIGHTENGINE_API_USER"), os.Getenv("SIGHTENGINE_API_SECRET")
			if u == "" || s == "" {
				return nil, fmt.Errorf("sightengine: set SIGHTENGINE_API_USER and SIGHTENGINE_API_SECRET")
			}
			out = append(out, sightengine{user: u, secret: s})
		default:
			return nil, fmt.Errorf("unknown classifier %q (want hive, sightengine)", n)
		}
	}
	return out, nil
}

func runClassifiers(cs []Classifier, path, format string, threshold float64) []Finding {
	var fs []Finding
	for _, c := range cs {
		if !c.Supports(format) {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		score, detail, err := c.Classify(ctx, path)
		cancel()
		f := Finding{Source: "remote:" + c.Name(), Location: "classifier", key: "remote:" + c.Name()}
		switch {
		case err != nil:
			f.Detail = "error: " + err.Error()
		case score >= threshold:
			f.Severity = SevStrong
			f.Detail = fmt.Sprintf("ai_generated score %.3f ≥ %.2f%s", score, threshold, detail)
		case score >= threshold/2:
			f.Severity = SevWeak
			f.Detail = fmt.Sprintf("ai_generated score %.3f%s", score, detail)
		default:
			f.Detail = fmt.Sprintf("ai_generated score %.3f%s", score, detail)
		}
		fs = append(fs, f)
	}
	return fs
}

func multipartUpload(ctx context.Context, url, path string, fields map[string]string, hdr http.Header) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)
	go func() {
		for k, v := range fields {
			mw.WriteField(k, v)
		}
		part, err := mw.CreateFormFile("media", filepath.Base(path))
		if err == nil {
			_, err = io.Copy(part, f)
		}
		if err == nil {
			err = mw.Close()
		}
		pw.CloseWithError(err)
	}()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, pr)
	if err != nil {
		return nil, err
	}
	for k, v := range hdr {
		req.Header[k] = v
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, clip(string(body), 200))
	}
	return body, nil
}

// ---------- Hive (image, video, audio — depends on the project the key belongs to) ----------

type hive struct{ key string }

func (hive) Name() string           { return "hive" }
func (hive) Supports(f string) bool { return true }

func (h hive) Classify(ctx context.Context, path string) (float64, string, error) {
	body, err := multipartUpload(ctx, "https://api.thehive.ai/api/v2/task/sync", path, nil,
		http.Header{"Authorization": {"Token " + h.key}})
	if err != nil {
		return 0, "", err
	}
	var doc any
	if err := json.Unmarshal(body, &doc); err != nil {
		return 0, "", fmt.Errorf("decode: %w", err)
	}
	// Response nests output[] per frame/segment, each with classes[{class,score}].
	// Take the max ai_generated across segments; report the top generator class.
	scores := map[string]float64{}
	walkClasses(doc, scores)
	ai, ok := scores["ai_generated"]
	if !ok {
		return 0, "", fmt.Errorf("no ai_generated class in response (is this key for an AI-detection project?)")
	}
	return ai, topSource(scores), nil
}

func walkClasses(v any, scores map[string]float64) {
	switch t := v.(type) {
	case map[string]any:
		if c, ok := t["class"].(string); ok {
			if s, ok := t["score"].(float64); ok && s > scores[c] {
				scores[c] = s
			}
		}
		for _, x := range t {
			walkClasses(x, scores)
		}
	case []any:
		for _, x := range t {
			walkClasses(x, scores)
		}
	}
}

func topSource(scores map[string]float64) string {
	type kv struct {
		k string
		v float64
	}
	var xs []kv
	for k, v := range scores {
		switch k {
		case "ai_generated", "not_ai_generated", "none", "inconclusive", "deepfake", "yes_deepfake", "no_deepfake":
			continue
		}
		xs = append(xs, kv{k, v})
	}
	sort.Slice(xs, func(i, j int) bool { return xs[i].v > xs[j].v })
	if len(xs) == 0 || xs[0].v < 0.5 {
		return ""
	}
	return fmt.Sprintf("; most likely source: %s (%.2f)", xs[0].k, xs[0].v)
}

// ---------- Sightengine (images) ----------

type sightengine struct{ user, secret string }

func (sightengine) Name() string { return "sightengine" }
func (sightengine) Supports(f string) bool {
	switch f {
	case "jpeg", "png", "webp", "gif":
		return true
	}
	return false
}

func (s sightengine) Classify(ctx context.Context, path string) (float64, string, error) {
	body, err := multipartUpload(ctx, "https://api.sightengine.com/1.0/check.json", path,
		map[string]string{"models": "genai", "api_user": s.user, "api_secret": s.secret}, nil)
	if err != nil {
		return 0, "", err
	}
	var r struct {
		Status string `json:"status"`
		Type   struct {
			AIGenerated *float64 `json:"ai_generated"`
		} `json:"type"`
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return 0, "", fmt.Errorf("decode: %w", err)
	}
	if r.Status != "success" || r.Type.AIGenerated == nil {
		return 0, "", fmt.Errorf("status %q: %s", r.Status, r.Error.Message)
	}
	return *r.Type.AIGenerated, "", nil
}

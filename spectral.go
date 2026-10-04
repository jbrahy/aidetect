package aidetect

// Spectral heuristic for neural-codec audio.
//
// Most current music generators (Suno, Udio, Stable Audio, MusicGen, ...)
// synthesise the waveform with a learned decoder built from strided
// transposed convolutions / upsampling layers. Those layers leave stationary,
// narrow spectral peaks at fixed frequencies (often a regular comb), present
// for the whole track regardless of what's being played. Deezer's research
// group showed this is enough to separate generator output from real
// recordings with a trivial classifier (Afchar et al., "Detecting music
// deepfakes is easy but actually hard", 2024).
//
// We measure exactly that: average the log spectrum over the whole track
// (musical notes move and wash out; fixed artifacts accumulate), take each
// bin's prominence over its neighbourhood above 4 kHz, count the narrow
// stationary peaks, and autocorrelate the prominence vector to find a comb.
//
// This is a heuristic, not a trained classifier. The thresholds are
// uncalibrated; it can be fooled by lossy re-encoding, pitch shifting, heavy
// mastering, or by human music that holds a high tone (loops, feedback, hum
// harmonics). It is reported as a weak signal only and can never by itself
// produce an AI-DECLARED verdict.

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"math/cmplx"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	fftSize      = 8192
	hopSize      = fftSize / 2
	maxSeconds   = 300
	peakMarginDB = 3.0 // prominence of a stationary peak in the time-averaged spectrum
	bandLowHz    = 4000.0
	bandGuardHz  = 1000.0
)

type SpectralMetrics struct {
	Decoder         string    `json:"decoder"`
	SampleRate      int       `json:"sample_rate"`
	Seconds         float64   `json:"seconds_analyzed"`
	Frames          int       `json:"frames"`
	BandwidthHz     float64   `json:"bandwidth_hz"`
	StationaryPeaks int       `json:"stationary_peaks"`
	PeakFreqsHz     []float64 `json:"peak_freqs_hz,omitempty"`
	CombSpacingHz   float64   `json:"comb_spacing_hz,omitempty"`
	CombStrength    float64   `json:"comb_strength"`
}

var audioRateRe = regexp.MustCompile(`Stream #\S+.*: Audio: .*?, (\d+) Hz`)

var errNoDecoder = errors.New("no decoder")

var lossyFormats = map[string]bool{"mp3": true, "mpeg-audio": true, "ogg": true, "isobmff": true, "matroska": true}

func spectralAnalyze(path string, format string, r io.ReaderAt, size int64, ffmpeg string) (*SpectralMetrics, []Finding, error) {
	var (
		pcm  []float32
		rate int
		dec  string
		err  error
	)
	if format == "wave" {
		pcm, rate, err = decodeWAV(r, size)
		dec = "native-wav"
	}
	if pcm == nil && ffmpeg != "" {
		pcm, rate, err = decodeFFmpeg(ffmpeg, path)
		dec = "ffmpeg"
	}
	if pcm == nil {
		if err == nil {
			err = errNoDecoder
		}
		return nil, nil, err
	}
	m := spectrum(pcm, rate)
	if m == nil {
		return nil, nil, fmt.Errorf("not enough non-silent audio to analyze")
	}
	m.Decoder = dec
	return m, spectralFindings(m, lossyFormats[format]), nil
}

func spectralFindings(m *SpectralMetrics, lossy bool) []Finding {
	detail := fmt.Sprintf("%d stationary HF peaks, comb strength %.2f", m.StationaryPeaks, m.CombStrength)
	if m.CombSpacingHz > 0 {
		detail += fmt.Sprintf(" @ %.1f Hz spacing", m.CombSpacingHz)
	}
	detail += fmt.Sprintf(", bandwidth %.1f kHz", m.BandwidthHz/1000)
	if lossy {
		detail += " (lossy source: less reliable)"
	}
	sev := SevInfo
	if m.StationaryPeaks >= 4 && m.CombStrength >= 0.3 || m.StationaryPeaks >= 10 {
		sev = SevWeak
		detail = "stationary spectral peaks consistent with neural-decoder upsampling artifacts: " + detail
	}
	return []Finding{{Source: "spectral", Severity: sev, Location: "audio signal", Detail: detail, key: "spectral"}}
}

func spectrum(pcm []float32, rate int) *SpectralMetrics {
	if rate <= 0 {
		return nil
	}
	if max := maxSeconds * rate; len(pcm) > max {
		off := (len(pcm) - max) / 2 // take the middle; skips intros/outros
		pcm = pcm[off : off+max]
	}
	half := fftSize/2 + 1
	win := make([]float64, fftSize)
	for i := range win {
		win[i] = 0.5 - 0.5*math.Cos(2*math.Pi*float64(i)/float64(fftSize-1))
	}
	sumDB := make([]float64, half)
	buf := make([]complex128, fftSize)
	frames := 0
	for off := 0; off+fftSize <= len(pcm); off += hopSize {
		var e float64
		for i := 0; i < fftSize; i++ {
			v := float64(pcm[off+i])
			e += v * v
			buf[i] = complex(v*win[i], 0)
		}
		if math.Sqrt(e/fftSize) < 1e-3 { // below -60 dBFS: skip silence
			continue
		}
		fft(buf)
		for k := 0; k < half; k++ {
			sumDB[k] += 20 * math.Log10(cmplx.Abs(buf[k])+1e-12)
		}
		frames++
	}
	if frames < 8 {
		return nil
	}
	binHz := float64(rate) / fftSize
	mean := make([]float64, half)
	for k := range mean {
		mean[k] = sumDB[k] / float64(frames)
	}

	m := &SpectralMetrics{SampleRate: rate, Frames: frames, Seconds: float64(len(pcm)) / float64(rate)}
	m.BandwidthHz = bandwidth(mean, binHz)

	lo := int(bandLowHz / binHz)
	// Stay clear of the low-pass/Nyquist edge: encoders and resamplers put
	// their own ripple there, which would read as stationary peaks.
	hi := int(math.Min(m.BandwidthHz-bandGuardHz, 0.95*float64(rate)/2) / binHz)
	if hi-lo < 64 {
		return m
	}
	prom := prominence(mean)
	for k := lo; k < hi; k++ {
		if prom[k] >= peakMarginDB && prom[k] >= prom[k-1] && prom[k] > prom[k+1] {
			m.StationaryPeaks++
			if len(m.PeakFreqsHz) < 24 {
				m.PeakFreqsHz = append(m.PeakFreqsHz, math.Round(float64(k)*binHz))
			}
		}
	}
	m.CombSpacingHz, m.CombStrength = comb(prom[lo:hi], binHz)
	return m
}

// prominence is how far each bin of the time-averaged spectrum stands above
// its ±16-bin neighbourhood (excluding ±2 around itself), clipped at 0. Only
// narrow, time-stationary tones survive averaging: notes that move wash out.
func prominence(mean []float64) []float64 {
	const w, g = 16, 2
	pre := make([]float64, len(mean)+1)
	for k, v := range mean {
		pre[k+1] = pre[k] + v
	}
	out := make([]float64, len(mean))
	for k := w; k < len(mean)-w; k++ {
		base := (pre[k+w+1] - pre[k-w] - (pre[k+g+1] - pre[k-g])) / float64(2*(w-g))
		if d := mean[k] - base; d > 0 {
			out[k] = d
		}
	}
	return out
}

// bandwidth: highest frequency whose smoothed mean level is within 50 dB of
// the 200 Hz–2 kHz reference. Informational (lossy encoders low-pass too).
func bandwidth(mean []float64, binHz float64) float64 {
	a, b := int(200/binHz), int(2000/binHz)
	if b <= a || b >= len(mean) {
		return float64(len(mean)) * binHz
	}
	var ref float64
	for k := a; k < b; k++ {
		ref += mean[k]
	}
	ref /= float64(b - a)
	const w = 8
	for k := len(mean) - w - 1; k > b; k-- {
		var s float64
		for j := -w; j <= w; j++ {
			s += mean[k+j]
		}
		if s/(2*w+1) > ref-50 {
			return float64(k) * binHz
		}
	}
	return float64(b) * binHz
}

// comb finds the lag (in Hz) at which the prominence vector best
// autocorrelates, i.e. peaks recurring at a regular spacing. Strength is the
// normalised autocorrelation at that lag, minus the median over all lags.
func comb(p []float64, binHz float64) (float64, float64) {
	var e float64
	for _, v := range p {
		e += v * v
	}
	if e == 0 {
		return 0, 0
	}
	minLag := int(math.Ceil(150 / binHz))
	maxLag := len(p) / 3
	if maxLag <= minLag {
		return 0, 0
	}
	acs := make([]float64, 0, maxLag-minLag)
	best, bestLag := -1.0, 0
	for L := minLag; L < maxLag; L++ {
		var s float64
		for k := 0; k+L < len(p); k++ {
			// ±1 bin tolerance: the comb rarely lands on exact bin multiples.
			s += p[k] * math.Max(p[k+L], math.Max(p[k+L-1], at(p, k+L+1)))
		}
		ac := s / e
		acs = append(acs, ac)
		if ac > best {
			best, bestLag = ac, L
		}
	}
	sort.Float64s(acs)
	strength := best - acs[len(acs)/2]
	if strength < 0 {
		strength = 0
	}
	return math.Round(float64(bestLag)*binHz*10) / 10, math.Round(strength*100) / 100
}

func at(p []float64, i int) float64 {
	if i < len(p) {
		return p[i]
	}
	return 0
}

// fft is an in-place iterative radix-2 Cooley–Tukey; len(a) must be a power of 2.
func fft(a []complex128) {
	n := len(a)
	for i, j := 1, 0; i < n; i++ {
		bit := n >> 1
		for ; j&bit != 0; bit >>= 1 {
			j ^= bit
		}
		j ^= bit
		if i < j {
			a[i], a[j] = a[j], a[i]
		}
	}
	for size := 2; size <= n; size <<= 1 {
		w := cmplx.Exp(complex(0, -2*math.Pi/float64(size)))
		for start := 0; start < n; start += size {
			wk := complex(1, 0)
			for k := 0; k < size/2; k++ {
				u, v := a[start+k], a[start+k+size/2]*wk
				a[start+k], a[start+k+size/2] = u+v, u-v
				wk *= w
			}
		}
	}
}

// ---------- decoders ----------

// decodeWAV reads PCM (8/16/24/32-bit int) or IEEE float WAV/RF64 and downmixes to mono.
func decodeWAV(r io.ReaderAt, size int64) ([]float32, int, error) {
	var (
		fmtChunk         []byte
		dataOff, dataLen int64
	)
	for off := int64(12); off+8 <= size; {
		h, err := readAt(r, off, 8)
		if err != nil || len(h) < 8 {
			break
		}
		n := int64(binary.LittleEndian.Uint32(h[4:8]))
		switch string(h[:4]) {
		case "fmt ":
			fmtChunk, _ = readAt(r, off+8, min64(n, 64))
		case "data":
			dataOff, dataLen = off+8, n
			if n == 0xFFFFFFFF || off+8+n > size {
				dataLen = size - dataOff
			}
		}
		if dataOff > 0 && fmtChunk != nil {
			break
		}
		off += 8 + n + n&1
	}
	if len(fmtChunk) < 16 || dataOff == 0 {
		return nil, 0, fmt.Errorf("wav: missing fmt or data chunk")
	}
	tag := binary.LittleEndian.Uint16(fmtChunk[0:2])
	ch := int(binary.LittleEndian.Uint16(fmtChunk[2:4]))
	rate := int(binary.LittleEndian.Uint32(fmtChunk[4:8]))
	bits := int(binary.LittleEndian.Uint16(fmtChunk[14:16]))
	if tag == 0xFFFE && len(fmtChunk) >= 26 {
		tag = binary.LittleEndian.Uint16(fmtChunk[24:26])
	}
	if ch <= 0 || rate <= 0 || (tag != 1 && tag != 3) {
		return nil, 0, fmt.Errorf("wav: unsupported format tag %#x", tag)
	}
	bps := bits / 8
	frame := int64(bps * ch)
	if frame == 0 {
		return nil, 0, fmt.Errorf("wav: bad block size")
	}
	nFrames := dataLen / frame
	if lim := int64(maxSeconds*2) * int64(rate); nFrames > lim { // read ≤ 2× what spectrum() keeps
		dataOff += (nFrames - lim) / 2 * frame
		nFrames = lim
	}
	raw, err := readAt(r, dataOff, nFrames*frame)
	if err != nil {
		return nil, 0, err
	}
	nFrames = int64(len(raw)) / frame
	out := make([]float32, nFrames)
	for i := int64(0); i < nFrames; i++ {
		var s float64
		for c := 0; c < ch; c++ {
			p := raw[i*frame+int64(c*bps):]
			s += sampleAt(p, tag, bits)
		}
		out[i] = float32(s / float64(ch))
	}
	return out, rate, nil
}

func sampleAt(p []byte, tag uint16, bits int) float64 {
	switch {
	case tag == 3 && bits == 32:
		return float64(math.Float32frombits(binary.LittleEndian.Uint32(p)))
	case tag == 3 && bits == 64:
		return math.Float64frombits(binary.LittleEndian.Uint64(p))
	case bits == 8:
		return (float64(p[0]) - 128) / 128
	case bits == 16:
		return float64(int16(binary.LittleEndian.Uint16(p))) / 32768
	case bits == 24:
		v := int32(uint32(p[0])<<8|uint32(p[1])<<16|uint32(p[2])<<24) >> 8
		return float64(v) / 8388608
	case bits == 32:
		return float64(int32(binary.LittleEndian.Uint32(p))) / 2147483648
	}
	return 0
}

// decodeFFmpeg decodes the first audio stream at its native rate to mono f32.
func decodeFFmpeg(ffmpeg, path string) ([]float32, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	rate := 0
	if probe, err := exec.LookPath("ffprobe"); err == nil {
		out, err := exec.CommandContext(ctx, probe, "-v", "error", "-select_streams", "a:0",
			"-show_entries", "stream=sample_rate", "-of", "csv=p=0", path).Output()
		if err == nil {
			rate, _ = strconv.Atoi(strings.TrimSpace(string(out)))
		}
	}
	if rate == 0 {
		// No ffprobe: read the rate from ffmpeg's own stream banner. Resampling
		// to a guessed rate would put the source's low-pass edge inside the
		// analysis band and show up as spurious "stationary peaks".
		var banner bytes.Buffer
		c := exec.CommandContext(ctx, ffmpeg, "-hide_banner", "-i", path)
		c.Stderr = &banner
		c.Run() // exits non-zero without an output file; the banner is what we want
		if m := audioRateRe.FindStringSubmatch(banner.String()); m != nil {
			rate, _ = strconv.Atoi(m[1])
		}
	}
	args := []string{"-v", "error", "-i", path, "-vn", "-map", "0:a:0", "-ac", "1"}
	if rate == 0 {
		rate = 48000
		args = append(args, "-ar", "48000")
	}
	args = append(args, "-t", strconv.Itoa(maxSeconds*2), "-f", "f32le", "pipe:1")
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, ffmpeg, args...)
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, 0, fmt.Errorf("ffmpeg: %v: %s", err, clip(stderr.String(), 200))
	}
	pcm := make([]float32, len(out)/4)
	for i := range pcm {
		pcm[i] = math.Float32frombits(binary.LittleEndian.Uint32(out[i*4:]))
	}
	return pcm, rate, nil
}

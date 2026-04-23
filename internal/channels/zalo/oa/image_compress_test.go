package oa

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"math/rand/v2"
	"testing"
)

// synthesizePNG encodes a PNG of the given dimensions. For the passthrough
// test we use a small solid image; for the shrink-over-cap test we fill
// with pseudo-random noise so PNG's DEFLATE can't collapse the output,
// producing a realistic multi-MB payload.
func synthesizePNG(t *testing.T, w, h int, noisy bool) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	if noisy {
		// Deterministic seed so the test is reproducible.
		r := rand.New(rand.NewPCG(42, 42))
		for y := 0; y < h; y++ {
			for x := 0; x < w; x++ {
				img.Set(x, y, color.RGBA{uint8(r.UintN(256)), uint8(r.UintN(256)), uint8(r.UintN(256)), 255})
			}
		}
	} else {
		for y := 0; y < h; y++ {
			for x := 0; x < w; x++ {
				img.Set(x, y, color.RGBA{uint8(x), uint8(y), uint8((x + y) % 256), 255})
			}
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("synthesize png: %v", err)
	}
	return buf.Bytes()
}

func TestCompressForZaloImage_UnderCapIsPassthrough(t *testing.T) {
	t.Parallel()
	data := synthesizePNG(t, 100, 100, false)
	cap := 1 << 20 // 1MB
	out, mt, err := compressForZaloImage(data, "image/png", cap)
	if err != nil {
		t.Fatalf("compress: %v", err)
	}
	if !bytes.Equal(out, data) {
		t.Errorf("expected passthrough when under cap, got re-encoded bytes")
	}
	if mt != "image/png" {
		t.Errorf("mime = %q, want image/png (unchanged)", mt)
	}
}

func TestCompressForZaloImage_ShrinksOverCap(t *testing.T) {
	t.Parallel()
	// 1500x1500 random-noise PNG ≈ 6-8 MB — DEFLATE can't compress noise.
	data := synthesizePNG(t, 1500, 1500, true)
	cap := 1 << 20 // 1MB
	if len(data) <= cap {
		t.Fatalf("synthesized PNG is only %d bytes; expected >1MB", len(data))
	}

	out, mt, err := compressForZaloImage(data, "image/png", cap)
	if err != nil {
		t.Fatalf("compress: %v", err)
	}
	if len(out) > cap {
		t.Errorf("compressed size %d still exceeds cap %d", len(out), cap)
	}
	if mt != "image/jpeg" {
		t.Errorf("mime = %q, want image/jpeg after compression", mt)
	}
}

func TestCompressForZaloImage_InvalidDataReturnsError(t *testing.T) {
	t.Parallel()
	// Pass a cap smaller than the garbage bytes so we actually reach the
	// decode step instead of early-returning via the under-cap passthrough.
	garbage := []byte("not an image, and definitely not bytes the image package can decode.")
	_, _, err := compressForZaloImage(garbage, "image/png", 10)
	if err == nil {
		t.Fatal("expected decode error on garbage bytes")
	}
}

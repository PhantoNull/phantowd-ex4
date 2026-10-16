// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package frontpaneltext_test

import (
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/frontpaneltext"
)

func TestPreparePreservesBytesWithoutHardwareClaims(t *testing.T) {
	for _, value := range []string{" ", "A", "NAS", "  NAS  ", "0rpm", "-1", "1025rpm", "~!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}", strings.Repeat("x", 255)} {
		prepared, err := frontpaneltext.Prepare(value, len(value))
		got, valid := prepared.Value()
		if err != nil || !valid || got != value {
			t.Fatalf("length %d: got (%q,%t,%v)", len(value), got, valid, err)
		}
	}
}

func TestPrepareRejectsMalformedWithoutPartialOutput(t *testing.T) {
	cases := []struct {
		text  string
		limit int
	}{
		{"", 20}, {"x", 0}, {"x", -1}, {"x", math.MinInt}, {"x", 256}, {"x", math.MaxInt},
		{"xx", 1}, {strings.Repeat("a", 256), 255}, {strings.Repeat("a", 1<<20), 255},
		{"\x00", 20}, {"a\x00b", 20}, {"a\nb", 20}, {"a\rb", 20}, {"\t", 20},
		{"\x1f", 20}, {"\x7f", 20}, {"\x80", 20}, {"\xfa", 20}, {"\xfb", 20}, {"\xff", 20},
		{"caffè", 20}, {"👻", 20}, {"e\u0301", 20}, {"\u00a0", 20}, {"\u202eNAS", 20},
	}
	for i, tc := range cases {
		prepared, err := frontpaneltext.Prepare(tc.text, tc.limit)
		if !errors.Is(err, frontpaneltext.ErrInvalid) || prepared != (frontpaneltext.Text{}) {
			t.Fatalf("case %d: failure did not return zero result/fixed error", i)
		}
		if got, valid := prepared.Value(); valid || got != "" {
			t.Fatalf("case %d: rejected text escaped", i)
		}
	}
}

func TestPrepareEveryByteAndInclusiveLimit(t *testing.T) {
	for b := 0; b <= 255; b++ {
		_, err := frontpaneltext.Prepare(string([]byte{byte(b)}), 1)
		want := b >= 0x20 && b <= 0x7e
		if (err == nil) != want {
			t.Fatalf("byte %#x", b)
		}
	}
	for limit := 1; limit <= 255; limit++ {
		for _, length := range []int{limit - 1, limit, limit + 1} {
			_, err := frontpaneltext.Prepare(strings.Repeat("a", length), limit)
			if (err == nil) != (length > 0 && length <= limit) {
				t.Fatalf("length %d/limit %d", length, limit)
			}
		}
	}
}

func TestTextStaysPrivateAndFailureDoesNotReusePriorValue(t *testing.T) {
	prior, err := frontpaneltext.Prepare("prior", 5)
	if err != nil {
		t.Fatal(err)
	}
	failed, err := frontpaneltext.Prepare("replacement", 5)
	if !errors.Is(err, frontpaneltext.ErrInvalid) {
		t.Fatal("oversize accepted")
	}
	if got, valid := failed.Value(); got != "" || valid {
		t.Fatal("failure supplied text")
	}
	if got, valid := prior.Value(); got != "prior" || !valid {
		t.Fatal("original value changed")
	}
	for _, value := range []any{prior, &prior, frontpaneltext.Text{}, &failed} {
		if _, err := json.Marshal(value); !errors.Is(err, frontpaneltext.ErrPrivate) {
			t.Fatal("JSON text escaped")
		}
	}
	if err := json.Unmarshal([]byte(`{}`), &prior); !errors.Is(err, frontpaneltext.ErrPrivate) {
		t.Fatal("JSON accepted")
	}
	if got, valid := prior.Value(); got != "prior" || !valid {
		t.Fatal("JSON changed prior value")
	}
}

func FuzzPrepare(f *testing.F) {
	for _, value := range []string{"", "NAS", " ", "0rpm", "a\x00b", "a\nb", "é", "\xfa\xfb", strings.Repeat("x", 255), strings.Repeat("x", 256)} {
		f.Add(value, 20)
		f.Add(value, 255)
	}
	f.Fuzz(func(t *testing.T, value string, limit int) {
		want := limit >= 1 && limit <= 255 && len(value) > 0 && len(value) <= limit
		if want {
			want = strings.IndexFunc(value, func(r rune) bool { return r < ' ' || r > '~' }) == -1
		}
		prepared, err := frontpaneltext.Prepare(value, limit)
		got, valid := prepared.Value()
		if want {
			if err != nil || !valid || got != value {
				t.Fatal("valid bytes changed or refused")
			}
		} else if !errors.Is(err, frontpaneltext.ErrInvalid) || valid || got != "" || prepared != (frontpaneltext.Text{}) {
			t.Fatal("invalid input accepted or retained")
		}
	})
}

func TestPrepareAllocations(t *testing.T) {
	value := strings.Repeat("x", 255)
	if got := testing.AllocsPerRun(1000, func() {
		prepared, err := frontpaneltext.Prepare(value, 255)
		if _, valid := prepared.Value(); err != nil || !valid {
			panic("preparation failed")
		}
	}); got != 0 {
		t.Fatalf("allocations: %v", got)
	}
}

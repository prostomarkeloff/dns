package dns

import (
	"strings"
	"testing"
)

func TestNSEC3LongSaltLength(t *testing.T) {
	salt := strings.Repeat("ab", 200) // 200-byte salt, RFC 5155 allows up to 255
	for _, s := range []string{
		"example.org. 3600 IN NSEC3 1 0 10 " + salt + " 2T7B4G4VSA5SMI47K61MV5BV1A22BOJR A RRSIG",
		"example.org. 3600 IN NSEC3PARAM 1 0 10 " + salt,
	} {
		rr, err := NewRR(s)
		if err != nil {
			t.Fatal(err)
		}
		var sl uint8
		switch v := rr.(type) {
		case *NSEC3:
			sl = v.SaltLength
		case *NSEC3PARAM:
			sl = v.SaltLength
		}
		t.Logf("%T SaltLength=%d (want 200)", rr, sl)
		if sl != 200 {
			t.Errorf("%T: SaltLength = %d, want 200", rr, sl)
		}
		buf := make([]byte, 2048)
		off, err := PackRR(rr, buf, 0, nil, false)
		if err != nil {
			t.Errorf("%T pack: %v", rr, err)
			continue
		}
		back, _, err := UnpackRR(buf[:off], 0)
		if err != nil {
			t.Errorf("%T unpack: %v", rr, err)
			continue
		}
		if !IsDuplicate(rr, back) {
			t.Errorf("%T round-trip differs:\n in: %s\nout: %s", rr, rr, back)
		}
	}
}

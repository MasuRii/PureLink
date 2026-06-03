package ip

import "testing"

func FuzzParse(f *testing.F) {
	for _, seed := range []string{"127.0.0.1", "::1", "2001:db8::1", "192.168.1.1", "", "not-an-ip"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		info, err := Parse(raw)
		if err != nil {
			return
		}
		if info.IP == "" || info.IsV4 == info.IsV6 {
			t.Fatalf("invalid parsed info: %+v", info)
		}
	})
}

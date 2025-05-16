package ipfilter

import (
	"testing"
)

func TestCIDRFilter_Allow(t *testing.T) {
	tests := []struct {
		name string
		cfg  *Config
		args map[string]bool
		want bool
	}{
		{
			name: "allow only",
			cfg: &Config{
				Allow: true,
				Cidr: []string{
					"127.0.0.1",
				},
			},
			args: map[string]bool{
				"127.0.0.1": true,
				"127.0.2.2": false,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ranger := NewIPFilter(tt.cfg)
			for ip, want := range tt.args {
				got := ranger.Allow(ip)
				if got != want {
					t.Errorf("Allow(%s) = %v, want %v", ip, got, want)
				}
			}
		})
	}
}

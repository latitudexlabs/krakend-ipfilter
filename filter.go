package ipfilter

import (
	"fmt"
	"net"
	"strings"

	"github.com/yl2chen/cidranger"
)

// IPFilter is a interface for allow or deny an ip
type IPFilter interface {
	Allow(ip string) bool
	Deny(ip string) bool
}

// NoopFilter noop, allow always, never deny
type NoopFilter struct{}

// Allow implement IPFilter.Allow
func (noop *NoopFilter) Allow(_ string) bool {
	return true
}

// Deny implement IPFilter.Deny
func (noop *NoopFilter) Deny(_ string) bool {
	return false
}

// CIDRFilter is an ip filter base on cidranger
type CIDRFilter struct {
	allow      bool
	cidrRanger cidranger.Ranger
}

func newRanger(ips []string) cidranger.Ranger {
	ranger := cidranger.NewPCTrieRanger()
	for _, ip := range ips {
		isCIDR := strings.IndexByte(ip, byte('/'))
		if isCIDR < 0 {
			ip = fmt.Sprintf("%s/24", ip)
		}
		_, ipNet, err := net.ParseCIDR(ip)
		if err != nil || ipNet == nil {
			continue
		}
		err = ranger.Insert(cidranger.NewBasicRangerEntry(*ipNet))
		if err != nil {
			continue
		}
	}
	return ranger
}

// NewIPFilter create a cidranger base ip filter
func NewIPFilter(cfg *Config) IPFilter {
	if cfg == nil {
		return &NoopFilter{}
	}
	return &CIDRFilter{
		allow:      cfg.Allow,
		cidrRanger: newRanger(cfg.Cidr),
	}
}

// Allow implement IPFilter.Allow
func (f *CIDRFilter) Allow(ip string) bool {
	netIP := net.ParseIP(ip)
	if netIP == nil {
		return false
	}

	if f.allow {
		if allow, err := f.cidrRanger.Contains(netIP); allow && err == nil {
			return true
		}
		return false
	} else {
		deny, err := f.cidrRanger.Contains(netIP)
		if deny || err != nil {
			return false
		}
		return true
	}
}

// Deny implement IPFilter.Deny
func (f *CIDRFilter) Deny(ip string) bool {
	return !f.Allow(ip)
}

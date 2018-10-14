package util

import (
	"bufio"
	"errors"
	"github.com/miekg/dns"
	"net"
	"os"
	"strings"
)

func SetECS(m *dns.Msg, addr net.IP) {
	if addr == nil {
		return
	}
	opt := m.IsEdns0()
	if opt == nil {
		opt = new(dns.OPT)
		opt.Hdr.Name = "."
		opt.Hdr.Rrtype = dns.TypeOPT
		m.Extra = append(m.Extra, opt)
	}
	var ecs *dns.EDNS0_SUBNET
	for _, val := range opt.Option {
		if v, ok := val.(*dns.EDNS0_SUBNET); ok {
			ecs = v
			break
		}
	}
	if ecs == nil {
		ecs = new(dns.EDNS0_SUBNET)
		opt.Option = append(opt.Option, ecs)
	}
	ecs.Code = dns.EDNS0SUBNET
	ecs.Address = addr
	if addr.To4() != nil {
		ecs.Family = 1         // 1 for IPv4 source address, 2 for IPv6
		ecs.SourceNetmask = 32 // 32 for IPV4, 128 for IPv6
	} else {
		ecs.Family = 2          // 1 for IPv4 source address, 2 for IPv6
		ecs.SourceNetmask = 128 // 32 for IPV4, 128 for IPv6
	}
	ecs.SourceScope = 0
}
func GetIPList(file string) (ipNets []*net.IPNet, err error) {
	f, err := os.Open(file)
	if err != nil {
		return
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		_, ipNet, err := net.ParseCIDR(scanner.Text())
		if err != nil {
			return nil, err
		}
		ipNets = append(ipNets, ipNet)
	}
	if err = scanner.Err(); err != nil {
		return nil, err
	}
	if len(ipNets) == 0 {
		return nil, errors.New("file is empty")
	}
	return
}
func IPListMatch(ip net.IP, ipNets []*net.IPNet) bool {
	for _, ipNet := range ipNets {
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}
func DomainMatch(domain string, domainList []string) bool {
	domain = "." + domain
	for _, val := range domainList {
		if strings.HasSuffix(domain, "."+val) {
			return true
		}
	}
	return false
}

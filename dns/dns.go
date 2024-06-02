package dns

import (
	"net"
	"slices"
	"strconv"
	"strings"
)

var RootServersIpv4 []net.IP = []net.IP{
	net.IPv4(198, 41, 0, 4),    // a
	net.IPv4(170, 247, 170, 2), // b
	net.IPv4(192, 33, 4, 12),   // c
}

func findIpv4AddrInAdditional(msg *Message, nameserver string) (net.IP, bool) {
	for _, rr := range msg.Additional {
		if rr_a, ok := rr.(*RR_A); ok {
			if rr_a.Name == nameserver {
				return rr_a.ToNetIp(), true
			}
		}
	}
	return nil, false
}

func findIpv6AddrInAdditional(msg *Message, nameserver string) (net.IP, bool) {
	for _, rr := range msg.Additional {
		if rr_aaaa, ok := rr.(*RR_AAAA); ok {
			if rr_aaaa.Name == nameserver {
				return rr_aaaa.ToNetIp(), true
			}
		}
	}
	return nil, false
}

func extractIpsFromRRs(rrs []RR) []net.IP {
	ips := []net.IP{}
	for _, rr := range rrs {
		if rr_a, ok := rr.(*RR_A); ok {
			ips = append(ips, rr_a.ToNetIp())
		} else if rr_aaaa, ok := rr.(*RR_AAAA); ok {
			ips = append(ips, rr_aaaa.ToNetIp())
		}
	}
	return ips
}

func extractIpFromRR(rr RR) net.IP {
	if rr_a, ok := rr.(*RR_A); ok {
		return rr_a.ToNetIp()
	} else if rr_aaaa, ok := rr.(*RR_AAAA); ok {
		return rr_aaaa.ToNetIp()
	}
	return nil
}

func splitNameIntoLabels(name string) []string {
	components := strings.Split(name, ".")
	for len(components) > 0 && len(components[len(components)-1]) == 0 {
		components = components[:len(components)-1]
	}
	return components
}

func compareNames(lhs, rhs string) bool {
	lhsLabels := splitNameIntoLabels(lhs)
	rhsLabels := splitNameIntoLabels(rhs)
	return slices.Equal(lhsLabels, rhsLabels)
}

func typeToString(t uint16) string {
	if v, ok := TypeString[t]; ok {
		return v
	} else {
		return strconv.FormatInt(int64(t), 10)
	}
}

func classToString(c uint16) string {
	if v, ok := ClassString[c]; ok {
		return v
	} else {
		return strconv.FormatInt(int64(c), 10)
	}
}

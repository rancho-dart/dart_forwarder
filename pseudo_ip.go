package main

// 当一台不支持Dart协议的主机查询位于其他域的主机域名时，按照DART协议的规则，返回DART网关的IP地址。这样，下一步它发送报文时会被发送到Dart网关
// 但是因为它不支持DART协议，它发送的是普通的IP报文，DART网关就不知道应该向何处转发
// 我们在此处为每一个被查询的域名生成一个唯一的伪地址返回给查询方。这个伪地址满足如下条件：
// 1. 伪地址不会出现在真实的网络中（不会被分配给真实的网络主机或设备）
// 2. 主机或路由器处理伪地址时，会把伪地址当成真实的地址一样对待
// 3. 伪地址池要足够大

import (
	"encoding/binary"
	"net"
	"sync"
	"time"
)

type PseudoIpEntry struct {
	Domain     string
	PseudoIP   net.IP
	RealIP     net.IP
	LastUsedAt time.Time
}

type PseudoIpPool struct {
	start     uint32
	end       uint32
	next      uint32
	ttl       time.Duration
	domainMap map[string]*PseudoIpEntry
	ipMap     map[uint32]*PseudoIpEntry
	mutex     sync.RWMutex
}

func NewPseudoIpPool(ttl time.Duration) *PseudoIpPool {
	start := ipToUint32(net.ParseIP("198.18.0.0"))
	end := ipToUint32(net.ParseIP("198.19.255.255"))
	return &PseudoIpPool{
		start:     start,
		end:       end,
		next:      start,
		ttl:       ttl,
		domainMap: make(map[string]*PseudoIpEntry),
		ipMap:     make(map[uint32]*PseudoIpEntry),
	}
}

// 分配或返回已有伪地址，并刷新时间
func (p *PseudoIpPool) Allocate(domain string, realIP net.IP) net.IP {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	// 若已存在，刷新时间与真实地址
	if entry, exists := p.domainMap[domain]; exists {
		entry.LastUsedAt = time.Now()
		entry.RealIP = realIP
		return entry.PseudoIP
	}

	// 分配新地址
	for i := uint32(0); i <= p.end-p.start; i++ {
		ipInt := p.start + ((p.next - p.start + i) % (p.end - p.start + 1))
		if _, used := p.ipMap[ipInt]; !used {
			pseudoIP := uint32ToIP(ipInt)
			entry := &PseudoIpEntry{
				Domain:     domain,
				PseudoIP:   pseudoIP,
				RealIP:     realIP,
				LastUsedAt: time.Now(),
			}
			p.domainMap[domain] = entry
			p.ipMap[ipInt] = entry
			p.next = ipInt + 1
			return pseudoIP
		}
	}
	return nil // 地址池耗尽
}

// 反查：伪地址 → 域名和真实地址
func (p *PseudoIpPool) Lookup(ip net.IP) (domain string, realIP net.IP, ok bool) {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	ipInt := ipToUint32(ip.To4())
	if entry, found := p.ipMap[ipInt]; found {
		return entry.Domain, entry.RealIP, true
	}
	return "", nil, false
}

// 清理过期项
func (p *PseudoIpPool) CleanupExpired() {
	if p.ttl == 0 {
		return
	}
	p.mutex.Lock()
	defer p.mutex.Unlock()

	now := time.Now()
	for ipInt, entry := range p.ipMap {
		if now.Sub(entry.LastUsedAt) > p.ttl {
			delete(p.ipMap, ipInt)
			delete(p.domainMap, entry.Domain)
		}
	}
}

// 工具函数
func ipToUint32(ip net.IP) uint32 {
	return binary.BigEndian.Uint32(ip.To4())
}

func uint32ToIP(i uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, i)
	return ip
}

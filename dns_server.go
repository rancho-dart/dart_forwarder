package main

import (
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// DNSServer 结构体，用于管理 DNS 服务
type DNSServer struct {
	ports []int
}

// ResolveARecord 递归解析 CNAME 链，直到得到最终的 A 记录
func ResolveARecord(domain, dnsServer string, depth int) ([]net.IP, bool, error) {
	if depth > 10 {
		return nil, false, fmt.Errorf("CNAME 链太长，疑似死循环")
	}

	c := new(dns.Client)
	c.Timeout = 3 * time.Second

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	m.RecursionDesired = true

	resp, _, err := c.Exchange(m, dnsServer+":53")
	if err != nil {
		return nil, false, err
	}

	var supportDart bool = false
	var aRecords []net.IP
	var lastCname string
	var cnameChain = make(map[string]struct{}, 10)
	cnameChain[domain] = struct{}{}

	for _, ans := range resp.Answer {
		// 如果cnameChain中不包含当前ans中的名称，则添加到cnameChain中
		rrName := ans.Header().Name
		if strings.HasPrefix(rrName, "dart-host.") || strings.HasPrefix(rrName, "dart-gateway.") {
			supportDart = true
		}

		switch rr := ans.(type) {
		case *dns.A:
			aRecords = append(aRecords, rr.A)
		case *dns.CNAME:
			_, exists := cnameChain[rrName]
			if !exists {
				continue
			}
			lastCname = rr.Target
			cnameChain[lastCname] = struct{}{} // Follow cname chain. if name in the chain, append cname to the chain
		}
	}

	if len(aRecords) > 0 {
		return aRecords, supportDart, nil
	} else if lastCname != "" {
		return ResolveARecord(lastCname, dnsServer, depth+1)
	}
	return nil, false, nil
}

func (s *DNSServer) ResolveFromParentDNSServer(fqdn string) (ip net.IP, supportDart bool) {
	for _, dnsServer := range CONFIG.Uplink.DNSServers {
		IPAddresses, supportDart, err := ResolveARecord(fqdn, dnsServer, 0)
		if err != nil {
			log.Printf("Error resolving A record for %s: %v\n", fqdn, err)
			continue
		} else if len(IPAddresses) == 0 {
			log.Printf("No A records found for %s\n", fqdn)
			return nil, false
		} else {
			return IPAddresses[0], supportDart
		}
	}
	return nil, false
}

func (s *DNSServer) Resolve(fqdn string) (outIfce *LinkInterface, ip net.IP, supportDart bool) {
	outIfce = s.getOutboundInfo(dns.Fqdn(fqdn)) // Only find in the downlink interfaces!
	if outIfce == nil {
		return nil, nil, false
	}

	dhcpServer, ok := dhcpServers[outIfce.Name()]
	if !ok {
		return nil, nil, false
	}

	lease, ok := dhcpServer.leasesByFQDN[fqdn]
	if !ok {
		return nil, nil, false
	}

	ip = lease.IP
	supportDart = lease.DARTVersion > 0
	return
}

// NewDNSServer 创建一个新的 DNS Server 实例
func NewDNSServer(ports []int) *DNSServer {
	return &DNSServer{
		ports: ports,
	}
}

// Start 启动 DNS Server
func (s *DNSServer) Start() {
	for _, port := range s.ports {
		go s.startServer(port)
	}
}

// startServer 在指定端口上启动 DNS 服务
func (s *DNSServer) startServer(port int) {
	server := &dns.Server{Addr: fmt.Sprintf(":%d", port), Net: "udp"}
	server.Handler = s
	fmt.Printf("DNS Server started on port %d\n", port)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Failed to start DNS server:[%v]\n", err)
	}
}

func (s *DNSServer) AuthorityFor(domain string) bool {
	for _, ifce := range CONFIG.Downlinks {
		if ifce.Domain == domain {
			return true
		}
	}
	return false
}

// ServeDNS 处理 DNS 查询
func (s *DNSServer) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {

	if r.Opcode == dns.OpcodeQuery && len(r.Question) > 0 {
		QueriedDomain := dns.Fqdn(strings.ToLower(r.Question[0].Name))

		Qtype := r.Question[0].Qtype

		if Qtype == dns.TypeA {
			s.ServerAQuery(w, r, QueriedDomain)
			return
		}

		if !(Qtype == dns.TypeSOA || Qtype == dns.TypeNS) {
			s.RespondWithNotImplemented(w, r)
			return
		}

		ParentInterfaceDomain := s.ParentInterfaceDomainOf(QueriedDomain) // 如果查询的域名在我的子域中，则返回子域的域名，否则返回空字符串
		isAuthority := s.AuthorityFor(QueriedDomain)                      // 下行接口之一的域名等于QueriedDomain？

		if isAuthority {
			switch Qtype {
			case dns.TypeSOA:
				s.RespondWithSOA(w, r, QueriedDomain, true)
			case dns.TypeNS:
				s.RespondWithNS(w, r, QueriedDomain)
			}
		} else if ParentInterfaceDomain != "" {
			s.RespondWithSOA(w, r, ParentInterfaceDomain, false)
		} else {
			s.RespondWithRefusal(w, r)
		}
		return
	}

	s.RespondWithNotImplemented(w, r)
}

func (s *DNSServer) ParentInterfaceDomainOf(queriedDomain string) string {
	for _, ifce := range CONFIG.Downlinks {
		if strings.HasSuffix(queriedDomain, "."+ifce.Domain) {
			return ifce.Domain
		}
	}
	return ""
}

func (s *DNSServer) RespondWithNS(w dns.ResponseWriter, r *dns.Msg, domain string) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	m.Rcode = dns.RcodeSuccess

	ns := &dns.NS{
		Hdr: dns.RR_Header{
			Name:   domain,
			Rrtype: dns.TypeNS,
			Class:  dns.ClassINET,
		},
		Ns: "ns." + domain,
	}
	m.Answer = append(m.Answer, ns)

	_, inboundIfce := s.getInboundInfo(w)
	glue := &dns.A{
		Hdr: dns.RR_Header{
			Name:   "ns." + domain,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
		},
		A: inboundIfce.Addr(),
	}
	m.Extra = append(m.Extra, glue)

	w.WriteMsg(m)
}

func (s *DNSServer) RespondWithSOA(w dns.ResponseWriter, r *dns.Msg, authorityDomain string, isAnswer bool) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	soa := &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   authorityDomain,
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		Ns:      "ns." + authorityDomain,
		Mbox:    "admin." + authorityDomain,
		Serial:  1,
		Refresh: 86400,
		Retry:   7200,
		Expire:  3600,
		Minttl:  3600,
	}

	if isAnswer {
		m.Rcode = dns.RcodeSuccess
		m.Answer = append(m.Answer, soa)
	} else {
		m.Rcode = dns.RcodeNameError
		m.Ns = append(m.Ns, soa)
	}

	w.WriteMsg(m)
}

func (s *DNSServer) RespondWithNotImplemented(w dns.ResponseWriter, r *dns.Msg) {
	dns.HandleFailed(w, r)
}

func (s *DNSServer) getInboundInfo(w dns.ResponseWriter) (clientIP net.IP, inboundIfce *LinkInterface) {
	IPstr := w.RemoteAddr().String()
	IPstr = IPstr[:strings.LastIndex(IPstr, ":")] // 去掉端口号
	clientIP = net.ParseIP(IPstr).To4()

	for i, ifce := range CONFIG.Downlinks {
		if ifce.ipNet.Contains(clientIP) {
			inboundIfce = &CONFIG.Downlinks[i].LinkInterface
			return clientIP, inboundIfce
		}
	}
	return clientIP, &CONFIG.Uplink.LinkInterface
}

func (s *DNSServer) ServerAQuery(w dns.ResponseWriter, r *dns.Msg, queriedDomain string) {
	// Mermaid Code:
	// graph TD
	// Start[开始查询] --> A{查询类型?}

	// %% 外网查内网分支
	// A -- 外网→内网 --> ReturnGateway[返回网关接口地址（For DART）]

	// %% 内网查外网分支
	// A -- 内网→外网 --> B{外网主机支持DART?}
	// B -- 是 --> C{内网主机支持DART?}
	// C -- 是 --> ReturnInternalGateway[返回网关内网接口地址（For Forward）]
	// C -- 否 --> ReturnFakeIP[返回伪地址（For NAT-4D）]
	// B -- 否 --> ReturnExtIP[返回外网主机IP（For NAT44）]

	// %% 新增内网查内网分支
	// A -- 内网→内网 --> D{同一内网?}
	// D -- 是 --> ReturnHostIP[返回主机IP（Direct）]
	// D -- 否 --> ReturnInternalGateway

	// %% 结果汇聚
	// ReturnGateway --> End[结束]
	// ReturnExtIP --> End
	// ReturnFakeIP --> End
	// ReturnInternalGateway --> End
	// ReturnHostIP --> End

	// 在DART协议中，每个子域都拥有完整的IPv4地址空间，因此这个接口可能收到来自任意地址的DNS Query报文
	// 本程序只是一个技术验证，使用轻量级的DNS库，不能返回接收到DNS Query报文的物理接口
	// 我们目前做一个简化设计，假设每个子域接口对应的是一个C类网段。我们比对发出报文的源地址和本机接口地址来推测接收到报文的接口

	clientIp, inboundIfce := s.getInboundInfo(w)
	outboundIfce := s.getOutboundInfo(queriedDomain)

	if outboundIfce == nil {
		s.RespondWithNxdomain(w, r)
		return
	}

	switch inLI := inboundIfce.Owner.(type) {
	case *UpLinkInterface:
		switch outLI := outboundIfce.Owner.(type) {
		case *UpLinkInterface:
			s.RespondWithRefusal(w, r)
		case *DownLinkInterface:
			s.RespondWithDartGateway(w, r, queriedDomain, outLI.Domain, inLI.ipNet.IP)
		}
		return
	case *DownLinkInterface:
		switch outLI := outboundIfce.Owner.(type) {
		case *UpLinkInterface:
			querierSupportDart := false
			if dhcpServer, ok := dhcpServers[inLI.Name]; ok { // 只有downlink接口才会开启DHCP SERVER
				lease, ok := dhcpServer.leasesByIp[clientIp.String()] // 看看查询方是不是通过DHCP获取的地址
				if ok && lease.DARTVersion == 1 {                     // 如果没记录，说明是静态配置IP的主机，默认其不支持DART；如果有分配记录，且DARTversion==0,还是不支持DART；
					querierSupportDart = true
				}
			}

			ipInParentDomain, queriedSupportDart := s.ResolveFromParentDNSServer(queriedDomain)
			if ipInParentDomain == nil {
				s.RespondWithNxdomain(w, r)
				return
			}

			if queriedSupportDart {
				if querierSupportDart {
					s.RespondWithDartGateway(w, r, queriedDomain, inLI.Domain, inLI.ipNet.IP)
				} else {
					// 这里需要传入已经查询到的真实地址以供分配伪地址
					s.RespondWithPseudoIp(w, r, queriedDomain, ipInParentDomain)
				}
			} else {
				// 被查询主机不支持DART，以真实的外部地址响应。主机发来报文时，目标地址不是伪地址，此时应当进行NAT44转换
				s.respondWithIP(w, r, queriedDomain, ipInParentDomain)
			}

			return
		case *DownLinkInterface:
			if inLI.Name == outLI.Name {
				// 同一子域内的主机互相查询，直接返回DHCP分配的IP地址
				s.respondWithDHCP(w, r, inLI.Name, queriedDomain)
			} else {
				// 这是两个子域之间的横向流量，我们直接返回网关地址。理论上直接交给操作系统转发也是可以的。所以我们返回入口网关地址
				s.RespondWithDartGateway(w, r, queriedDomain, inLI.Domain, inLI.ipNet.IP)
			}
			return
		}
	}
	s.RespondWithRefusal(w, r)
}

// getOutboundInfo 找到与域名最长匹配的接口
func (s *DNSServer) getOutboundInfo(domain string) *LinkInterface {
	var BestMatch *DownLinkInterface

	for i, iface := range CONFIG.Downlinks {
		if strings.HasSuffix(domain, iface.Domain) && (BestMatch == nil || len(iface.Domain) > len((BestMatch.Domain))) {
			BestMatch = &CONFIG.Downlinks[i]
		}
	}

	if BestMatch != nil {
		return &BestMatch.LinkInterface
	} else {
		return &CONFIG.Uplink.LinkInterface
	}
}

func (s *DNSServer) respondWithIP(w dns.ResponseWriter, r *dns.Msg, domain string, ip net.IP) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Answer = append(m.Answer, &dns.A{
		Hdr: dns.RR_Header{
			Name:   domain,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    60,
		},
		A: ip,
	})
	w.WriteMsg(m)
}

func (s *DNSServer) RespondWithPseudoIp(w dns.ResponseWriter, r *dns.Msg, domain string, ip net.IP) {
	// 只有内网不支持DART协议的主机查询外网域名的时候才需要以伪地址响应

	// 在返回伪地址之前，我们先查询到真实地址。这样，客户机发送报文到对方的时候，马上就能从伪地址映射表中拿到真实地址
	pseudoIp := PSEUDO_POOL.FindOrAllocate(domain, ip, DARTPort) // 我们主动发起连接的时候，目标主机必须在默认的DARTPort收取UDP报文

	if pseudoIp == nil {
		s.respondWithServerFailure(w, r)
		return
	}
	s.respondWithIP(w, r, domain, pseudoIp)
}

func (s *DNSServer) RespondWithDartGateway(w dns.ResponseWriter, r *dns.Msg, domain string, gwDomain string, gwIP net.IP) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	cname := &dns.CNAME{
		Hdr:    dns.RR_Header{Name: domain, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
		Target: fmt.Sprintf("dart-gateway.%s", gwDomain),
	}
	m.Answer = append(m.Answer, cname)

	a := &dns.A{
		Hdr: dns.RR_Header{Name: cname.Target, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   gwIP,
	}
	m.Answer = append(m.Answer, a)

	w.WriteMsg(m)
}

// RespondWithRefusal 以“拒绝服务”进行响应
func (s *DNSServer) RespondWithRefusal(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Rcode = dns.RcodeRefused
	w.WriteMsg(m)
}

func (s *DNSServer) RespondWithNxdomain(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	m.Rcode = dns.RcodeNameError
	w.WriteMsg(m)
}

func (s *DNSServer) respondWithServerFailure(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Rcode = dns.RcodeServerFailure
	w.WriteMsg(m)
}

// respondWithDHCP 查询 DHCP SERVER 分配的地址并进行响应
func (s *DNSServer) respondWithDHCP(w dns.ResponseWriter, dnsMsg *dns.Msg, ifName, domain string) {
	var ip net.IP
	var supportDart bool

	dhcpServer, ok := dhcpServers[ifName]
	if !ok {
		s.RespondWithRefusal(w, dnsMsg)
		return
	}

	lease, ok := dhcpServer.leasesByFQDN[domain]
	if !ok {
		s.RespondWithNxdomain(w, dnsMsg)
		return
	}

	ip = lease.IP
	supportDart = lease.DARTVersion > 0

	// 构建 DNS 响应
	m := new(dns.Msg)
	m.SetReply(dnsMsg)
	m.Authoritative = true

	if supportDart {
		// Example:
		// root@c1:~# dig +noall +answer  c1.sh.cn
		// c1.sh.cn.               60      IN      CNAME   dart-host.c1.sh.cn.
		// dart-host.c1.sh.cn.     60      IN      A       10.0.0.99

		// c1.sh.cn is firstly resolved to a 'dart-host.' prefixed canme dart-host.c1.sh.cn, which means this host
		// supports DART protocol, then dart-host.c1.sh.cn is resolved to the IP address of the host

		cname := &dns.CNAME{
			Hdr:    dns.RR_Header{Name: domain, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
			Target: fmt.Sprintf("dart-host.%s", domain),
		}
		m.Answer = append(m.Answer, cname)

		a := &dns.A{
			Hdr: dns.RR_Header{Name: cname.Target, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   ip,
		}
		m.Answer = append(m.Answer, a)
	} else {
		// Example:
		// root@c1:~# dig +noall +answer c2.sh.cn
		// c2.sh.cn.               60      IN      A       10.0.0.100

		// c2.sh.cn is resolved to the IP address of the host directly, without a 'dart-host.' prefixed cname as bridge
		// because it doesn't support DART protocol

		a := &dns.A{
			Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   ip,
		}
		m.Answer = append(m.Answer, a)
	}

	w.WriteMsg(m)
}

// startDNSServerModule 启动 DNS Server 模块
var PSEUDO_POOL *PseudoIpPool
var DNS_SERVER = NewDNSServer([]int{53})

func startDNSServerModule() {
	PSEUDO_POOL = NewPseudoIpPool(time.Hour)

	// 创建并启动 DNS Server
	DNS_SERVER.Start()
}

package main

import (
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const (
	DART_GATEWAY_PREFIX = "dart-gateway."
	DART_HOST_PREFIX    = "dart-host."
	NAME_SERVER_PREFIX  = "ns."
)

// DNSServer 结构体，用于管理 DNS 服务
type DNSServer struct {
	ports []int
}

func resolveNsRecord(domain, dnsServer string) (addrs []net.IP, err error) {
	c := new(dns.Client)
	c.Timeout = 3 * time.Second

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeNS)
	m.RecursionDesired = true

	resp, _, err := c.Exchange(m, dnsServer+":53")
	if err != nil {
		return nil, fmt.Errorf("failed to query NS records for %s: %v", domain, err)
	}

	if resp.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("DNS query for %s returned non-success Rcode: %d", domain, resp.Rcode)
	}

	// 提取 NS 记录
	var nsRecords []string
	for _, ans := range resp.Answer {
		if ns, ok := ans.(*dns.NS); ok {
			nsRecords = append(nsRecords, ns.Ns)
		}
	}

	// 提取胶水记录中的 IP 地址
	for _, rr := range resp.Extra {
		if a, ok := rr.(*dns.A); ok {
			for _, ns := range nsRecords {
				if a.Hdr.Name == ns {
					addrs = append(addrs, a.A)
				}
			}
		}
	}

	if len(addrs) == 0 {
		return nil, fmt.Errorf("no glue records found for NS records of %s", domain)
	}

	return addrs, nil
}

// resolveARecord 递归解析 CNAME 链，直到得到最终的 A 记录
func resolveARecord(domain, dnsServer string, depth int) (addrs []net.IP, supportDart bool, err error) {
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

	var suppDart bool = false
	var aRecords []net.IP
	var lastCname string
	var cnameChain = make(map[string]struct{}, 10)
	cnameChain[domain] = struct{}{}

	for _, ans := range resp.Answer {
		// 如果cnameChain中不包含当前ans中的名称，则添加到cnameChain中
		rrName := ans.Header().Name
		if strings.HasPrefix(rrName, DART_HOST_PREFIX) || strings.HasPrefix(rrName, DART_GATEWAY_PREFIX) {
			suppDart = true
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
		return aRecords, suppDart, nil
	} else if lastCname != "" {
		return resolveARecord(lastCname, dnsServer, depth+1)
	}
	return nil, false, nil
}

func findSubDomainUnder(domain, base string) (string, bool) {
	_domain := "." + domain
	_base := "." + base
	if !strings.HasSuffix(_domain, _base) {
		return "", false
	}

	// 去掉 base 前面的部分，找到前一个 label
	prefix := strings.TrimSuffix(_domain, _base)

	// 找到最后一个 "."，表示下一个上级域的边界
	lastDot := strings.LastIndex(prefix, ".")
	if lastDot == -1 {
		return "", false
	}

	// 拼回一个完整的 "xxx.base"
	return _domain[lastDot+1:], true
}

func (s *DNSServer) lookup(fqdn string) (outIfce *LinkInterface, ip net.IP, supportDart bool) {
	outIfce = s.getOutboundInfo(dns.Fqdn(fqdn)) // Only find in the downlink interfaces!
	if outIfce != nil {
		dhcpServer, ok := DHCP_SERVERS[outIfce.Name()]
		if ok {
			subDomain, ok := findSubDomainUnder(fqdn, dhcpServer.dlIfce.Domain)
			if ok {
				lease, ok := dhcpServer.leasesByFQDN[subDomain]
				if ok {
					ip = lease.IP
					supportDart = lease.DARTVersion > 0
					return outIfce, ip, supportDart
				}
			}
		}
	}
	return nil, nil, false
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
	log.Printf("DNS Server started on port %d\n", port)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Failed to start DNS server:[%v]\n", err)
	}
}

func (s *DNSServer) respondAsDomainAgent(Qtype uint16, queriedDomain string, outLI *DownLinkInterface, inLI *LinkInterface, w dns.ResponseWriter, r *dns.Msg) {
	switch Qtype {
	case dns.TypeA:
		if queriedDomain == outLI.Domain || queriedDomain == DART_GATEWAY_PREFIX+outLI.Domain || queriedDomain == NAME_SERVER_PREFIX+outLI.Domain {
			s.respondWithDartGateway(w, r, queriedDomain, outLI.Domain, inLI.ipNet().IP, false) // 如果查询的是网关本身，那么返回不带CNAME的网关地址（因为网关本身不支持DART协议栈:-) ）
		} else {
			s.respondWithDartGateway(w, r, queriedDomain, outLI.Domain, inLI.ipNet().IP, true) // 从父域查询子域的A记录，一律以上联口的IP作答
		}
	case dns.TypeSOA:
		s.respondWithSOA(w, r, queriedDomain, queriedDomain == outLI.Domain) // 从父域查询子域的SOA记录，假如是子域，则回答SOA记录
	case dns.TypeNS:
		if queriedDomain == outLI.Domain {
			s.respondWithNS(w, r, queriedDomain, inLI.ipNet().IP, true) // 从父域查询子域的NS记录。一律回答“我就是该域的名字服务器”
		} else {
			s.respondWithSOA(w, r, queriedDomain, false)
		}
	}
}

// ServeDNS 处理 DNS 查询
func (s *DNSServer) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {

	if r.Opcode == dns.OpcodeQuery && len(r.Question) > 0 {
		queriedDomain := dns.Fqdn(strings.ToLower(r.Question[0].Name))

		Qtype := r.Question[0].Qtype

		clientIp, inboundIfce := s.getInboundInfo(w)

		// 先处理反查域名的请求
		if Qtype == dns.TypePTR && r.Question[0].Qclass == dns.ClassINET {
			rIP := net.ParseIP(strings.TrimSuffix(queriedDomain, ".in-addr.arpa.")).To4()
			if rIP != nil {
				queriedIP := fmt.Sprintf("%d.%d.%d.%d", rIP[3], rIP[2], rIP[1], rIP[0])
				dhcpServer, ok := DHCP_SERVERS[inboundIfce.Name()]
				if ok {
					lease, ok := dhcpServer.leasesByIp[queriedIP]
					if ok {
						s.respondWithPtr(w, r, queriedDomain, lease.FQDN)
						return
					}
				}
			}
		}

		outboundIfce := s.getOutboundInfo(queriedDomain)

		if outboundIfce == nil {
			s.respondWithServerFailure(w, r)
			return
		}

		switch inLI := inboundIfce.Owner.(type) {
		case *UpLinkInterface:
			switch outLI := outboundIfce.Owner.(type) {
			case *UpLinkInterface:
				s.respondWithRefusal(w, r) // 从父域查询父域的记录，理论上不会发给我。假如收到，一律拒绝。
				return
			case *DownLinkInterface:
				s.respondAsDomainAgent(Qtype, queriedDomain, outLI, &inLI.LinkInterface, w, r)
			}
		case *DownLinkInterface:
			switch outLI := outboundIfce.Owner.(type) {
			case *UpLinkInterface:
				// 从子域查询父域的记录
				querierSupportDart := false
				if DHCP_SERVER, ok := DHCP_SERVERS[inLI.Name]; ok { // 只有downlink接口才会开启DHCP SERVER
					lease, ok := DHCP_SERVER.leasesByIp[clientIp.String()] // 看看查询方是不是通过DHCP获取的地址
					if ok && lease.DARTVersion == 1 {                      // 如果没记录，说明是静态配置IP的主机，默认其不支持DART；如果有分配记录，且DARTversion==0,还是不支持DART；
						querierSupportDart = true
					}
				}

				ipInParentDomain, queriedSupportDart := outLI.resolveA(queriedDomain)
				if ipInParentDomain == nil {
					s.respondWithNxdomain(w, r)
					return
				}

				// 如果被查询方支持DART
				if queriedSupportDart {
					switch Qtype {
					case dns.TypeA:
						if querierSupportDart {
							s.respondWithDartGateway(w, r, queriedDomain, inLI.Domain, inLI.ipNet.IP, true)
						} else {
							s.respondWithPseudoIp(w, r, queriedDomain, ipInParentDomain)
						}
						return
					default:
						s.respondWithCName(w, r, queriedDomain, inLI.Domain)
						return
					}
				} else {
					// 如果被查询方不支持DART，则以真实地址作答，后面转发时会进行NAT44转换。对于SOA和NS查询当以父域的记录作答
					s.respondWithForwardQuery(w, r)
					return
				}
			case *DownLinkInterface:
				// 这是子域查询子域的记录

				if outLI.Name != inLI.Name {
					// 从一个子域查询另一个子域的记录
					s.respondAsDomainAgent(Qtype, queriedDomain, outLI, &inLI.LinkInterface, w, r)
					return
				}

				level1SubDomain, ok := findSubDomainUnder(queriedDomain, outLI.Domain)
				if !ok {
					// 能够走到这里，查询的域名应当属于出接口的域，所以不可能不ok
					s.respondWithServerFailure(w, r)
					return
				}

				if level1SubDomain != queriedDomain {
					// 这是下联口域中主机查询下联口域的子域
					s.respondWithDelegate(w, r, outLI.Name, level1SubDomain)
					return
				}

				switch Qtype {
				case dns.TypeA:
					// 同一子域内的主机互相查询，直接返回DHCP分配的IP地址
					if queriedDomain == inLI.Domain || queriedDomain == DART_GATEWAY_PREFIX+inLI.Domain || queriedDomain == NAME_SERVER_PREFIX+inLI.Domain {
						s.respondWithDartGateway(w, r, queriedDomain, inLI.Domain, inLI.ipNet.IP, false)
						return
					} else {
						s.respondWithLeasedIP(w, r, inLI.Name, queriedDomain)
						return
					}
				case dns.TypeSOA:
					s.respondWithSOA(w, r, queriedDomain, queriedDomain == outLI.Domain) // 从子域查询子域的SOA记录。一律回答“我就是该域的权威服务器”
					return
				case dns.TypeNS:
					// 同一个接口，意味着同一个DART域。
					var ip net.IP
					if inLI.Domain == queriedDomain {
						ip = inLI.ipNet.IP
						s.respondWithNS(w, r, queriedDomain, ip, true)
					} else { // queriedDomin 是 inLI.Domain域内的主机
						if inLI.RegistedInUplinkDNS {
							ip, _, _, delegated := s.getDhcpLeasedIp(inLI.Name, queriedDomain)
							if delegated {
								s.respondWithNS(w, r, queriedDomain, ip, true) // 这个域名被委派了子域，以NS作答
							} else {
								// 是域内的主机，但并没有派生出子域
								s.respondWithSOA(w, r, queriedDomain, false)
							}
						} else {
							// 如果当前接口的域并没有注册到上级DNS，那么无法派生出可解析的子域（因为如果允许，那么其发出的报文的DART源地址无法解析到正确的IP）
							s.respondWithSOA(w, r, queriedDomain, false)
						}
					}
					return
				}
			}
		}
	}

	s.respondWithNotImplemented(w, r)
}

func (s *DNSServer) respondWithDelegate(w dns.ResponseWriter, r *dns.Msg, name string, level1SubDomain string) {
	ip, _, _, isDelegated := s.getDhcpLeasedIp(name, level1SubDomain)
	if isDelegated && ip != nil {
		s.respondWithNS(w, r, level1SubDomain, ip, false)
	} else {
		s.respondWithSOA(w, r, level1SubDomain, false)
	}
}

func (s *DNSServer) respondWithPtr(w dns.ResponseWriter, r *dns.Msg, queriedReverseName string, hostname string) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	m.Answer = append(m.Answer, &dns.PTR{
		Hdr: dns.RR_Header{
			Name:   queriedReverseName, // e.g. "25.2.0.192.in-addr.arpa."
			Rrtype: dns.TypePTR,
			Class:  dns.ClassINET,
			Ttl:    60,
		},
		Ptr: dns.Fqdn(hostname), // e.g. "example.com."
	})
	w.WriteMsg(m)
	log.Printf("respondWithPtr: %s -> %s", queriedReverseName, hostname)
}

func (s *DNSServer) respondWithCName(w dns.ResponseWriter, r *dns.Msg, queriedDomain string, domain string) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	cname := &dns.CNAME{
		Hdr:    dns.RR_Header{Name: queriedDomain, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
		Target: domain,
	}
	m.Answer = append(m.Answer, cname)

	w.WriteMsg(m)
}

func forwardQuery(r *dns.Msg, upstream string) (*dns.Msg, error) {
	c := new(dns.Client)
	c.Net = "udp"
	c.Timeout = 2 * time.Second

	resp, _, err := c.Exchange(r, upstream+":53")
	if err != nil {
		return nil, err
	}
	return resp, nil
}
func (s *DNSServer) respondWithForwardQuery(w dns.ResponseWriter, r *dns.Msg) {
	for _, dnsServer := range CONFIG.Uplink.DNSServers {
		resp, err := forwardQuery(r, dnsServer)
		if err == nil {
			// 将上游响应直接写回客户端
			w.WriteMsg(resp)
			return
		}
	}

	log.Printf("Forward failed")
	s.respondWithServerFailure(w, r)
}

func (s *DNSServer) respondWithNS(w dns.ResponseWriter, r *dns.Msg, domain string, ip net.IP, nsQueried bool) {
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

	if nsQueried {
		// 如果客户查询的是NS记录，那么放在Answer区
		m.Answer = append(m.Answer, ns)
	} else {
		// 如果是因为客户实际查询的是被委托区域的域名，服务器必须返回NS记录以告知查询方：你查询的域名由这台NS服务器来解析。
		// 此时我们就应该将NS记录放在Ns区
		m.Ns = append(m.Ns, ns)
	}

	glue := &dns.A{
		Hdr: dns.RR_Header{
			Name:   "ns." + domain,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
		},
		A: ip,
	}
	m.Extra = append(m.Extra, glue)

	w.WriteMsg(m)
}

func (s *DNSServer) respondWithSOA(w dns.ResponseWriter, r *dns.Msg, authorityDomain string, isAnswer bool) {
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

func (s *DNSServer) respondWithNotImplemented(w dns.ResponseWriter, r *dns.Msg) {
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

// getOutboundInfo
func (s *DNSServer) getOutboundInfo(domain string) *LinkInterface {
	var Match *DownLinkInterface

	for i, iface := range CONFIG.Downlinks {
		if strings.HasSuffix("."+domain, "."+iface.Domain) {
			Match = &CONFIG.Downlinks[i]
			break
		}
	}

	if Match != nil {
		return &Match.LinkInterface
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

func (s *DNSServer) respondWithPseudoIp(w dns.ResponseWriter, r *dns.Msg, domain string, ip net.IP) {
	// 只有内网不支持DART协议的主机查询外网域名的时候才需要以伪地址响应

	// 在返回伪地址之前，我们先查询到真实地址。这样，客户机发送报文到对方的时候，马上就能从伪地址映射表中拿到真实地址
	pseudoIp := PSEUDO_POOL.FindOrAllocate(domain, ip, DARTPort) // 我们主动发起连接的时候，目标主机必须在默认的DARTPort收取UDP报文

	if pseudoIp == nil {
		s.respondWithServerFailure(w, r)
		return
	}
	s.respondWithIP(w, r, domain, pseudoIp)
}

func (s *DNSServer) respondWithDartGateway(w dns.ResponseWriter, r *dns.Msg, domain string, gwdomain string, gwIP net.IP, withCName bool) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	var AName string

	if withCName {
		AName = DART_GATEWAY_PREFIX + gwdomain
		cname := &dns.CNAME{
			Hdr:    dns.RR_Header{Name: domain, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
			Target: AName,
		}
		m.Answer = append(m.Answer, cname)
	} else {
		AName = domain
	}

	a := &dns.A{
		Hdr: dns.RR_Header{Name: AName, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   gwIP,
	}
	m.Answer = append(m.Answer, a)

	w.WriteMsg(m)
}

// respondWithRefusal 以“拒绝服务”进行响应
func (s *DNSServer) respondWithRefusal(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Rcode = dns.RcodeRefused
	w.WriteMsg(m)
}

func (s *DNSServer) respondWithNxdomain(w dns.ResponseWriter, r *dns.Msg) {
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

func (s *DNSServer) getDhcpLeasedIp(ifName, domain string) (ip net.IP, supportDart bool, isStatic bool, delegated bool) {
	dhcpServer, ok := DHCP_SERVERS[ifName]
	if ok {
		// lease, ok := dhcpServer.staticLeases[domain] // 先查静态绑定，因为地址分配之后，静态绑定的条目也会被加入分配表中
		var staticLease *leaseInfo
		for _, lease := range dhcpServer.staticLeases {
			if lease.FQDN == domain {
				staticLease = &lease
				break
			}
		}

		if staticLease != nil {
			return staticLease.IP, staticLease.DARTVersion > 0, true, staticLease.Delegated
		}

		lease, ok := dhcpServer.leasesByFQDN[domain]
		if ok {
			return lease.IP, lease.DARTVersion > 0, true, false
		}
	}
	return nil, false, false, false
}

// respondWithLeasedIP 查询 DHCP SERVER 分配的地址并进行响应
func (s *DNSServer) respondWithLeasedIP(w dns.ResponseWriter, dnsMsg *dns.Msg, ifName, domain string) {
	// TODO: 这里要区分是本域的还是子域的域名
	ip, supportDart, _, delegated := s.getDhcpLeasedIp(ifName, domain)
	if ip == nil {
		s.respondWithNxdomain(w, dnsMsg)
		return
	}

	// 构建 DNS 响应
	m := new(dns.Msg)
	m.SetReply(dnsMsg)
	m.Authoritative = true

	if supportDart && !delegated { // 当前实现比较简单，所有DART网关本身还不支持DART协议
		// Example:
		// root@c1:~# dig +noall +answer  c1.sh.cn
		// c1.sh.cn.               60      IN      CNAME   dart-host.c1.sh.cn.
		// dart-host.c1.sh.cn.     60      IN      A       10.0.0.99

		// c1.sh.cn is firstly resolved to a 'dart-host.' prefixed cname dart-host.c1.sh.cn, which means this host
		// supports DART protocol, then dart-host.c1.sh.cn is resolved to the IP address of the host

		cname := &dns.CNAME{
			Hdr:    dns.RR_Header{Name: domain, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
			Target: DART_HOST_PREFIX + domain,
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
	PSEUDO_POOL = NewPseudoIpPool(time.Hour, PSEUDO_IP_POOL) // 当前给地址池设置的TTL为1小时。1小时内保证不会被清理。两种情况下会启动地址池清理：1.地址池耗竭；2.每天凌晨3点。

	// 创建并启动 DNS Server
	DNS_SERVER.Start()
}

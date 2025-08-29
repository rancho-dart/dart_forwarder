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

// 将 dns.Client 提升为全局变量，避免每次查询都创建新对象
var dnsClient = &dns.Client{
	Timeout: 3 * time.Second,
}

func writeMsgWithDebug(w dns.ResponseWriter, m *dns.Msg) {
	// if !strings.Contains(m.Question[0].Name, "ubuntu") {
	// 	logIf("debug1", "===== DNS response: %s", m.String())
	// }
	err := w.WriteMsg(m)
	if err != nil {
		logIf(Error, "failed to write response:", err)
	}
}

func resolveByQuery(domain, dnsServer string, depth int) (addrs []net.IP, supportDart bool, err error) {
	if depth > 10 {
		return nil, false, fmt.Errorf("CNAME 链太长，疑似死循环")
	}

	// 每次递归调用创建独立的 dns.Client 实例  // ChatGPT说递归调用中反复使用同一个 dns.Client 实例是安全的，不会产生资源冲突
	// c := &dns.Client{
	//     Timeout: 3 * time.Second,
	// }

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	m.RecursionDesired = true

	// 插入EDNS0 Option，表明自己是DART网关
	opt := &dns.OPT{
		Hdr: dns.RR_Header{
			Name:   ".",
			Rrtype: dns.TypeOPT,
		},
	}
	// 假设 DARTOption 是 uint16 类型的 EDNS option code
	opt.Option = append(opt.Option, &dns.EDNS0_LOCAL{
		Code: DARTOption,
		Data: []byte{1}, // 可以根据实际需要设置 Data
	})

	m.Extra = append(m.Extra, opt)
	// 使用独立的 dns.Client 进行查询
	resp, _, err := dnsClient.Exchange(m, dnsServer+":53")
	if err != nil {
		return nil, false, err
	}

	var suppDart bool = false
	var aRecords []net.IP
	var lastCname string
	var cnameChain = make(map[string]struct{}, 10)
	cnameChain[domain] = struct{}{}

	for _, ans := range resp.Answer {
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
			cnameChain[lastCname] = struct{}{}
		}
	}

	if len(aRecords) > 0 {
		return aRecords, suppDart, nil
	} else if lastCname != "" {
		return resolveByQuery(lastCname, dnsServer, depth+1)
	}
	return nil, false, nil
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
	if len(resp.Extra) == 0 {
		for _, ns := range nsRecords {
			nsips, _, _ := resolveByQuery(ns, dnsServer, 0) // 如果没有额外的记录，尝试通过查询域名来获取 IP 地址
			addrs = append(addrs, nsips...)
		}
	} else {
		for _, rr := range resp.Extra {
			if a, ok := rr.(*dns.A); ok {
				for _, ns := range nsRecords {
					if a.Hdr.Name == ns {
						addrs = append(addrs, a.A)
					}
				}
			}
		}
	}

	if len(addrs) == 0 {
		return nil, fmt.Errorf("no glue records found for NS records of %s", domain)
	}

	return addrs, nil
}

func findSubDomainUnder(domain, base string) (level1SubDomain string, isSubDomain bool) {
	// If domain ends with base (i.e., domain is a subdomain of base), return the part of domain that is one level deeper than base.
	// The purpose is that when the DART gateway forwards packets, it needs to know to whom to forward the packet.
	// If the destination address domain is several levels deeper than base, the gateway only forwards to the gateway one level deeper.

	_domain := "." + domain
	_base := "." + base
	if !strings.HasSuffix(_domain, _base) {
		return "", false
	}

	// Remove the base part from the end, and find the previous label.
	prefix := strings.TrimSuffix(_domain, _base)

	// Find the last ".", which marks the boundary of the next higher-level domain.
	lastDot := strings.LastIndex(prefix, ".")
	if lastDot == -1 {
		// This is the case where domain == base.
		return "", false
	}

	// Reconstruct a complete "xxx.base"
	return _domain[lastDot+1:], true
}

func (s *DNSServer) getForwardInfo(fqdn string) (outboundIfce *LinkInterface, lease *leaseInfo) {
	outboundIfce = s.getOutboundIfce(dns.Fqdn(fqdn))

	if outboundIfce != nil {
		dhcpServer, ok := DHCP_SERVERS[outboundIfce.Name()] // Note that DHCP Servers are only enabled on DownLink interfaces.
		if ok {
			subDomain, ok := findSubDomainUnder(fqdn, dhcpServer.dlIfce.Domain)
			if ok {
				lease = dhcpServer.leasesByFQDN[subDomain]
			}
		}
	}
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
	logIf(Info, "DNS Server started\n")
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Failed to start DNS server:[%v]\n", err)
	}
}

func (s *DNSServer) respondAsDomainAgent(Qtype uint16, queriedDomain string, outLI *DownLinkInterface, inLI *LinkInterface, w dns.ResponseWriter, r *dns.Msg) {
	var ip net.IP
	switch LI := inLI.Owner.(type) {
	case *UpLinkInterface:
		if LI.ResolvableIP != nil {
			ip = LI.ResolvableIP
		} else {
			ip = LI.ipNet.IP
		}
	case *DownLinkInterface:
		ip = LI.ipNet.IP
	}

	switch Qtype {
	case dns.TypeA:
		if queriedDomain == outLI.Domain || queriedDomain == DART_GATEWAY_PREFIX+outLI.Domain || queriedDomain == NAME_SERVER_PREFIX+outLI.Domain {
			s.respondWithDartGateway(w, r, queriedDomain, outLI.Domain, ip, false) // 如果查询的是网关本身，那么返回不带CNAME的网关地址（因为网关本身不支持DART协议栈:-) ）
		} else {
			s.respondWithDartGateway(w, r, queriedDomain, outLI.Domain, ip, true) // 从父域查询子域的A记录，一律以上联口的IP作答
		}
	case dns.TypeSOA:
		s.respondWithSOA(w, r, queriedDomain, queriedDomain == outLI.Domain) // 从父域查询子域的SOA记录，假如是子域，则回答SOA记录
	case dns.TypeNS:
		if queriedDomain == outLI.Domain {
			s.respondWithNS(w, r, queriedDomain, ip, true) // 从父域查询子域的NS记录。一律回答“我就是该域的名字服务器”
		} else {
			s.respondWithSOA(w, r, queriedDomain, false)
		}
	}
}

func (s *DNSServer) querierSupportDart(ifceName string, querierIP net.IP, r *dns.Msg) bool {
	if DHCP_SERVER, ok := DHCP_SERVERS[ifceName]; ok { // 只有downlink接口才会开启DHCP SERVER
		lease, ok := DHCP_SERVER.leasesByIp[querierIP.String()] // 看看查询方是不是通过DHCP获取的地址
		if ok {                                                 // 如果有分配记录
			if lease.DARTVersion > 0 { // 通过DARTVersion即可判断是否支持DART
				return true
			}

			if lease.Delegated { // 但DART网关更复杂一点。可能DART网关本身不支持DART，但其上运行的dartd是支持DART的，此时需要通过EDNS0选项来判断
				// 一台DART网关在向上级DART网关发出DNS查询的时候，会在EDNS0选项中携带DART选项，通过检查这个选项来判断查询方是否支持DART协议
				for _, extra := range r.Extra {
					if opt, ok := extra.(*dns.OPT); ok {
						for _, option := range opt.Option {
							if option.Option() == DARTOption {
								return true
							}
						}
					}
				}
			}
		} //如果没记录，说明是静态配置IP的主机，默认其不支持DART
	} // 如果接口上没有开启DHCP SERVER，默认其不支持DART

	return false
}

// ServeDNS 处理 DNS 查询
func (s *DNSServer) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {

	if r.Opcode == dns.OpcodeQuery && len(r.Question) > 0 {
		queriedDomain := dns.Fqdn(strings.ToLower(r.Question[0].Name))

		Qtype := r.Question[0].Qtype

		clientIp, inboundIfce := s.getInboundInfo(w)
		if !strings.Contains(queriedDomain, "ubuntu") && clientIp.String() != "127.0.0.1" {
			logIf(Debug1, "Received DNS query from interface %s ip %s for %s, Qtype: %d", inboundIfce.Name(), clientIp.String(), queriedDomain, Qtype)
		}

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

		outboundIfce := s.getOutboundIfce(queriedDomain)

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
				return
			default:
				s.respondWithRefusal(w, r)
				logIf(Error, "unknown outbound interface type: %v", outLI)
				return
			}
		case *DownLinkInterface:
			switch outboundLI := outboundIfce.Owner.(type) {
			case *UpLinkInterface:
				// 从子域查询父域的记录

				// 查询方有两种可能：支持DART，或者不支持。而DART网关作为特例，又存在两种情况：
				// 1.操作系统本身不支持DART（因为它是IPv4-only的网关）
				// 2.其上运行的dartd服务支持DART协议。
				querierSupportDart := s.querierSupportDart(inLI.Name, clientIp, r)

				ipInParentDomain, _, queriedSupportDart := outboundLI.resolveWithCache(queriedDomain)
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
							var baseDomain string
							if outboundLI.inRootDomain {
								baseDomain = ""
							} else {
								baseDomain = inLI.Domain
							}
							s.respondWithPseudoIp(w, r, queriedDomain, baseDomain, ipInParentDomain)
						}
						return
					default:
						s.respondWithCName(w, r, queriedDomain, inLI.Domain)
						return
					}
				} else {
					// 如果被查询方不支持DART，则以真实地址作答，后面转发时会进行NAT44转换。对于SOA和NS查询当以父域的记录作答
					// s.respondWithForwardQuery(w, r, CONFIG.Uplink.DNSServers)
					if inLI.NAT44enabled {
						s.respondWithARecord(w, r, queriedDomain, ipInParentDomain)
					} else {
						s.respondWithRefusal(w, r) // 如果不支持NAT44，那么拒绝服务
					}
					return
				}
			case *DownLinkInterface:
				// 这是子域查询子域的记录

				if outboundLI.Name != inLI.Name {
					// 从一个子域查询另一个子域的记录
					// 本程序是作为DART协议的原型开发的，目前没有计划支持同一网关中同一父域下多个子域之间的互通，因此请不要对这种情况进行测试。
					// s.respondAsDomainAgent(Qtype, queriedDomain, outLI, &inLI.LinkInterface, w, r)
					s.respondWithRefusal(w, r)
					return
				}

				// 以下发生在同一子域接口配置的DART域内

				// 如果执行到这里，说明查询的域名要么是接口域名本身，要么比接口域名只深1级
				switch Qtype {
				case dns.TypeA:
					// 同一子域内的主机互相查询，直接返回DHCP分配的IP地址
					s.handleQueryInsideSubDomain(w, r, outboundLI, clientIp, queriedDomain)
					return
				case dns.TypeSOA:
					s.respondWithSOA(w, r, queriedDomain, queriedDomain == outboundLI.Domain) // 从子域查询子域的SOA记录。一律回答“我就是该域的权威服务器”
					return
				case dns.TypeNS:
					// 同一个接口，意味着同一个DART域内的查询
					var ip net.IP
					if inLI.Domain == queriedDomain {
						ip = inLI.ipNet.IP
						s.respondWithNS(w, r, queriedDomain, ip, true)
					} else {
						// queriedDomin 是 inLI.Domain域内的主机
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
				case dns.TypeAAAA:
					s.respondWithNxdomain(w, r) // DART协议目前只支持IPv4地址
					return
				default:
					logIf(Error, "Unsupported DNS query type: %d for %s", Qtype, queriedDomain)
					s.respondWithNotImplemented(w, r) // 其他类型的查询不支持
					return
				}
			default:
				logIf(Error, "Unknown outbound interface type: %T", outboundLI)
				return
			}
		default:
			logIf(Error, "Unknown inbound interface type: %T", inLI)
			return
		}
	}

	logIf(Error, "Unsupported DNS query: %s, opcode is %d", r.Question[0].Name, r.Opcode)
	s.respondWithNotImplemented(w, r)
}

func (s *DNSServer) handleQueryInsideSubDomain(w dns.ResponseWriter, r *dns.Msg, dlIfce *DownLinkInterface, querierIP net.IP, queriedDomain string) {
	// 处理在子域内的查询
	if dlIfce.Domain == queriedDomain || queriedDomain == DART_GATEWAY_PREFIX+dlIfce.Domain || queriedDomain == NAME_SERVER_PREFIX+dlIfce.Domain {
		// 如果查询的是接口域名本身，或者两个内置的域名（dart-gateway.<domain>和ns.<domain>），那么直接返回接口的IP地址
		s.respondWithDartGateway(w, r, queriedDomain, dlIfce.Domain, dlIfce.ipNet.IP, false)
		return
	}

	// 判断查询方是否支持DART
	querierSupportDart := s.querierSupportDart(dlIfce.Name, querierIP, r)

	// 判断被查询方是否支持DART
	_, queriedLease := s.getForwardInfo(queriedDomain)
	if queriedLease == nil {
		s.respondWithNxdomain(w, r)
		return
	}

	queriedSupportDart := queriedLease.DARTVersion > 0
	queriedIsGateway := false
	if !queriedSupportDart && queriedLease.Delegated {
		if dlIfce != nil {
			// 如果被查询方支持DART，那么返回A记录
			if len(queriedDomain) > len(queriedLease.FQDN) {
				queriedSupportDart = true
				queriedIsGateway = true
			}
		}
	}

	switch {
	case !queriedSupportDart && !querierSupportDart:
		// 双方均不支持DART，返回A记录
		if queriedLease.IP == nil {
			s.respondWithNxdomain(w, r)
		} else {
			s.respondWithARecord(w, r, queriedDomain, queriedLease.IP)
		}
	case !queriedSupportDart && querierSupportDart:
		// 被查询方不支持DART，查询方支持DART，分配伪地址，返回DART网关
		pseudoIp := PSEUDO_POOL.FindOrAllocate(queriedDomain, queriedLease.IP, DARTPort).To4() // 我们主动发起连接的时候，目标主机必须在默认的DARTPort收取UDP报文
		if pseudoIp == nil {
			s.respondWithServerFailure(w, r)
			return
		}

		s.respondWithDartGateway(w, r, queriedDomain, getParentDomain(queriedDomain), dlIfce.Addr(), true) // 返回DART网关
	case queriedSupportDart && querierSupportDart:
		// 双方都支持DART，返回CNAME转接的真实IP。
		s.respondWithDartStyle(w, r, queriedLease.IP, queriedDomain, queriedIsGateway)
	case queriedSupportDart && !querierSupportDart:
		// 被查询方支持DART，查询方不支持DART，返回伪地址
		s.respondWithPseudoIp(w, r, queriedDomain, dlIfce.Domain, queriedLease.IP)
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
	writeMsgWithDebug(w, m)
	logIf(Debug1, "respondWithPtr: %s -> %s", queriedReverseName, hostname)
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

	writeMsgWithDebug(w, m)
	logIf(Debug1, "respondWithCName: %s -> %s", queriedDomain, domain)
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

	writeMsgWithDebug(w, m)
	logIf(Debug1, "respondWithNS: %s -> %s", domain, ip.String())
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

	writeMsgWithDebug(w, m)
	logIf(Debug2, "respondWithSOA: %s", authorityDomain)
}

func (s *DNSServer) respondWithNotImplemented(w dns.ResponseWriter, r *dns.Msg) {
	dns.HandleFailed(w, r)
	logIf(Error, "DNS query not implemented: %s", r.Question[0].Name)
}

func (s *DNSServer) getInboundInfo(w dns.ResponseWriter) (clientIP net.IP, inboundIfce *LinkInterface) {
	IPstr := w.RemoteAddr().String()
	IPstr = IPstr[:strings.LastIndex(IPstr, ":")] // 去掉端口号
	clientIP = net.ParseIP(IPstr).To4()

	// github.com/miekg/dns不会提供查询报文进入的网络接口，因此我们在这里进行判断
	// 这里判断规则还是基于这样的认定：所有进入下联口的查询报文都与接口处于同一网段
	// 如果严格按照DART协议的定义，每个DART域享有完整的IPv4地址空间，是不能通过源地址来判断进入的接口的。
	// 作为原型系统，我们简单点
	if CONFIG.RouterOnAStickIfce == nil {
		for i, ifce := range CONFIG.Downlinks {
			if ifce.ipNet.Contains(clientIP) {
				inboundIfce = &CONFIG.Downlinks[i].LinkInterface
				return
			}
		}
		inboundIfce = &CONFIG.Uplink.LinkInterface
		return
	} else {
		// 单臂路由
		if CONFIG.RouterOnAStickIfce.ipNet.Contains(clientIP) {
			inboundIfce = &CONFIG.RouterOnAStickIfce.LinkInterface
			return
		}
		inboundIfce = &CONFIG.Uplink.LinkInterface
		return
	}
}

// getOutboundIfce
func (s *DNSServer) getOutboundIfce(domain string) *LinkInterface {
	// 通过匹配后缀判断报文该从哪个接口发送。如果子接口均不匹配，则默认从 uplink 发送
	for i, iface := range CONFIG.Downlinks {
		if strings.HasSuffix("."+domain, "."+iface.Domain) {
			return &CONFIG.Downlinks[i].LinkInterface
		}
	}

	return &CONFIG.Uplink.LinkInterface
}

func getParentDomain(domain string) string {
	firstDot := strings.Index(domain, ".")
	if firstDot == -1 {
		return ""
	} else {
		return domain[firstDot+1:]
	}
}

func (s *DNSServer) respondWithPseudoIp(w dns.ResponseWriter, r *dns.Msg, domain, baseDomain string, ip net.IP) {
	// 只有内网不支持DART协议的主机查询外网域名或者子域域名的时候才需要以伪地址响应

	// 在返回伪地址之前，我们先查询到真实地址。这样，客户机发送报文到对方的时候，马上就能从伪地址映射表中拿到真实地址
	pseudoIp := PSEUDO_POOL.FindOrAllocate(domain, ip, DARTPort).To4() // 我们主动发起连接的时候，目标主机必须在默认的DARTPort收取UDP报文

	if pseudoIp == nil {
		s.respondWithServerFailure(w, r)
		return
	}

	m := new(dns.Msg)
	m.SetReply(r)

	AName := fmt.Sprintf("[%s].%s", ip.String(), baseDomain) // "[]"实际上不属于合法的DNS字符集，不过看起来客户端也不会验证其合法性。这种返回格式不是DART协议的一部分，只是试图返回一个对人稍微有点意义的CNAME

	m.Answer = append(m.Answer, &dns.CNAME{
		Hdr: dns.RR_Header{
			Name:   domain,
			Rrtype: dns.TypeCNAME,
			Class:  dns.ClassINET,
			Ttl:    60,
		},
		Target: AName,
	})

	m.Answer = append(m.Answer, &dns.A{
		Hdr: dns.RR_Header{
			Name:   AName,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    60,
		},
		A: pseudoIp,
	})

	writeMsgWithDebug(w, m)

	logIf(Debug1, "respondWithPseudoIp: %s -> %s", domain, pseudoIp.String())
}

func (s *DNSServer) respondWithARecord(w dns.ResponseWriter, r *dns.Msg, domain string, IP net.IP) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	a := &dns.A{
		Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   IP,
	}
	m.Answer = append(m.Answer, a)

	writeMsgWithDebug(w, m)
	logIf(Debug1, "respondWithARecord: %s -> %s", domain, IP.String())
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

	writeMsgWithDebug(w, m)
	logIf(Debug1, "respondWithDartGateway: %s -> %s", domain, gwIP.String())
}

// respondWithRefusal 以“拒绝服务”进行响应
func (s *DNSServer) respondWithRefusal(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Rcode = dns.RcodeRefused
	writeMsgWithDebug(w, m)
	logIf(Debug2, "respondWithRefusal: %s", r.Question[0].Name)
}

func (s *DNSServer) respondWithNxdomain(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	m.Rcode = dns.RcodeNameError
	writeMsgWithDebug(w, m)
	logIf(Debug2, "respondWithNxdomain: %s", r.Question[0].Name)
}

func (s *DNSServer) respondWithServerFailure(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Rcode = dns.RcodeServerFailure
	writeMsgWithDebug(w, m)
	logIf(Error, "respondWithServerFailure: %s", r.Question[0].Name)
}

func (s *DNSServer) getDhcpLeaseByFqdn(ifName, fqdn string) *leaseInfo {
	dhcpServer, ok := DHCP_SERVERS[ifName]
	if ok {
		for i := range dhcpServer.staticLeases {
			if dhcpServer.staticLeases[i].FQDN == fqdn {
				lease := dhcpServer.staticLeases[i]
				return lease
			}
		}

		lease, ok := dhcpServer.leasesByFQDN[fqdn]
		if ok {
			return lease
		}
	}
	return nil
}

func (s *DNSServer) getDhcpLeasedIp(ifName, domain string) (ip net.IP, supportDart bool, isStatic bool, delegated bool) {
	dhcpServer, ok := DHCP_SERVERS[ifName]
	if ok {
		// lease, ok := dhcpServer.staticLeases[domain] // 先查静态绑定，因为地址分配之后，静态绑定的条目也会被加入分配表中
		var staticLease *leaseInfo
		for _, lease := range dhcpServer.staticLeases {
			if lease.FQDN == domain {
				staticLease = lease
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

// respondWithDartStyle 查询 DHCP SERVER 分配的地址并进行响应
func (s *DNSServer) respondWithDartStyle(w dns.ResponseWriter, dnsMsg *dns.Msg, ip net.IP, domain string, isGateway bool) {
	// 构建 DNS 响应
	m := new(dns.Msg)
	m.SetReply(dnsMsg)
	m.Authoritative = true

	var cnameTarget string
	parentDomain := getParentDomain(domain)
	if isGateway { // 当前实现比较简单，所有DART网关本身还不支持DART协议
		cnameTarget = fmt.Sprintf("%s%s", DART_GATEWAY_PREFIX, parentDomain)
	} else {
		cnameTarget = fmt.Sprintf("%s%s", DART_HOST_PREFIX, parentDomain)
	}

	// Example:
	// root@c1:~# dig +noall +answer  c1.sh.cn
	// c1.sh.cn.               60      IN      CNAME   dart-host.c1.sh.cn.
	// dart-host.c1.sh.cn.     60      IN      A       10.0.0.99

	// c1.sh.cn is firstly resolved to a 'dart-host.' prefixed cname dart-host.c1.sh.cn, which means this host
	// supports DART protocol, then dart-host.c1.sh.cn is resolved to the IP address of the host

	cname := &dns.CNAME{
		Hdr:    dns.RR_Header{Name: domain, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
		Target: cnameTarget, // dart-host.c1.sh.cn or dart-gateway.c1.sh.cn
	}
	m.Answer = append(m.Answer, cname)

	a := &dns.A{
		Hdr: dns.RR_Header{Name: cname.Target, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   ip,
	}
	m.Answer = append(m.Answer, a)

	writeMsgWithDebug(w, m)
	logIf(Debug1, "respondWithLeasedIP: %s -> %s", domain, ip.String())
}

// startDNSServerModule 启动 DNS Server 模块
var PSEUDO_POOL *PseudoIpPool
var DNS_SERVER = NewDNSServer([]int{53})

func startDNSServerModule() {
	PSEUDO_POOL = NewPseudoIpPool(time.Hour, PSEUDO_IP_POOL) // 当前给地址池设置的TTL为1小时。1小时内保证不会被清理。两种情况下会启动地址池清理：1.地址池耗竭；2.每天凌晨3点。

	// 创建并启动 DNS Server
	DNS_SERVER.Start()
}

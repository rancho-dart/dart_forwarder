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
	domain_t := "." + domain
	base_t := "." + base
	if !strings.HasSuffix(domain_t, base_t) {
		return "", false
	}

	// 去掉 base 前面的部分，找到前一个 label
	prefix := strings.TrimSuffix(domain_t, base_t)

	// 找到最后一个 "."，表示下一个上级域的边界
	lastDot := strings.LastIndex(prefix, ".")
	if lastDot == -1 { 
		return "", false
	}

	// 拼回一个完整的 "xxx.base"
	return domain_t[lastDot+1:], true
}
func (s *DNSServer) resolve(fqdn string) (outIfce *LinkInterface, ip net.IP, supportDart bool) {
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

// ServeDNS 处理 DNS 查询
func (s *DNSServer) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {

	if r.Opcode == dns.OpcodeQuery && len(r.Question) > 0 {
		queriedDomain := dns.Fqdn(strings.ToLower(r.Question[0].Name))

		Qtype := r.Question[0].Qtype

		clientIp, inboundIfce := s.getInboundInfo(w)

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
				switch Qtype {
				case dns.TypeA:
					s.respondWithDartGateway(w, r, queriedDomain, outLI.Domain, inLI.ipNet.IP, true) // 从父域查询子域的A记录，一律以上联口的IP作答
					return
				case dns.TypeSOA:
					s.respondWithSOA(w, r, queriedDomain, queriedDomain == outLI.Domain) // 从父域查询子域的SOA记录，假如是子域，则回答SOA记录
					return
				case dns.TypeNS:
					if queriedDomain == outLI.Domain {
						s.respondWithNS(w, r, queriedDomain, inLI.ipNet.IP) // 从父域查询子域的NS记录。一律回答“我就是该域的名字服务器”
					} else {
						s.respondWithSOA(w, r, queriedDomain, false)
					}
					return
				}
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

				ipInParentDomain, queriedSupportDart := outLI.resolveFromParentDNSServer(queriedDomain)
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
				switch Qtype {
				case dns.TypeA:
					if inLI.Name == outLI.Name {
						// 同一子域内的主机互相查询，直接返回DHCP分配的IP地址
						if queriedDomain == DART_GATEWAY_PREFIX+inLI.Domain {
							s.respondWithDartGateway(w, r, queriedDomain, inLI.Domain, inLI.ipNet.IP, false)
							return
						} else if queriedDomain == inLI.Domain || queriedDomain == "ns."+inLI.Domain {
							s.respondWithDartGateway(w, r, queriedDomain, inLI.Domain, inLI.ipNet.IP, true)
						} else {
							s.respondWithDHCP(w, r, inLI.Name, queriedDomain)
							return
						}
					} else {
						// 这是两个子域之间的横向流量，我们直接返回网关地址。理论上直接交给操作系统转发也是可以的。所以我们返回入口网关地址
						s.respondWithDartGateway(w, r, queriedDomain, inLI.Domain, inLI.ipNet.IP, true)
						return
					}
				case dns.TypeSOA:
					s.respondWithSOA(w, r, queriedDomain, queriedDomain == outLI.Domain) // 从子域查询子域的SOA记录。一律回答“我就是该域的权威服务器”
					return
				case dns.TypeNS:
					if inLI.Name == outLI.Name {
						// 同一个接口，意味着同一个DART域。
						var ip net.IP
						if inLI.Domain == queriedDomain {
							ip = inLI.ipNet.IP
							s.respondWithNS(w, r, queriedDomain, ip)
						} else { // queriedDomin 是 inLI.Domain的子域
							if inLI.RegistedInUplinkDNS {
								ip, _ = s.getDhcpLeasedIp(inLI.Name, queriedDomain)
								s.respondWithNS(w, r, queriedDomain, ip)
							} else {
								s.respondWithSOA(w, r, queriedDomain, false) // 如果当前接口的域并没有注册到上级DNS，那么无法派生出可解析的子域
							}
						}
						return
					} else {
						if queriedDomain == outLI.Domain {
							s.respondWithNS(w, r, queriedDomain, inLI.ipNet.IP)
						} else {
							s.respondWithSOA(w, r, queriedDomain, false)
						}
						return
					}
				}
			}
		}
	}

	s.respondWithNotImplemented(w, r)
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

func (s *DNSServer) respondWithNS(w dns.ResponseWriter, r *dns.Msg, domain string, ip net.IP) {
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

// getOutboundInfo 找到与域名最长匹配的接口
func (s *DNSServer) getOutboundInfo(domain string) *LinkInterface {
	var Match *DownLinkInterface

	for i, iface := range CONFIG.Downlinks {
		if strings.HasSuffix("."+domain, "."+iface.Domain) {
			Match = &CONFIG.Downlinks[i]
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

func (s *DNSServer) respondWithDartGateway(w dns.ResponseWriter, r *dns.Msg, domain string, gwDomain string, gwIP net.IP, withCName bool) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	AName := DART_GATEWAY_PREFIX + gwDomain

	if withCName {
		cname := &dns.CNAME{
			Hdr:    dns.RR_Header{Name: domain, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
			Target: AName,
		}
		m.Answer = append(m.Answer, cname)
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

func (s *DNSServer) getDhcpLeasedIp(ifName, domain string) (net.IP, bool) {
	dhcpServer, ok := DHCP_SERVERS[ifName]
	if ok {
		lease, ok := dhcpServer.leasesByFQDN[domain]
		if ok {
			return lease.IP, lease.DARTVersion > 0
		}
	}
	return nil, false
}

// respondWithDHCP 查询 DHCP SERVER 分配的地址并进行响应
func (s *DNSServer) respondWithDHCP(w dns.ResponseWriter, dnsMsg *dns.Msg, ifName, domain string) {

	ip, supportDart := s.getDhcpLeasedIp(ifName, domain)
	if ip == nil {
		s.respondWithNxdomain(w, dnsMsg)
		return
	}

	// 构建 DNS 响应
	m := new(dns.Msg)
	m.SetReply(dnsMsg)
	m.Authoritative = true

	if supportDart {
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
	PSEUDO_POOL = NewPseudoIpPool(time.Hour)

	// 创建并启动 DNS Server
	DNS_SERVER.Start()
}

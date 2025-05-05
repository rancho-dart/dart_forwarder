package main

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// DNSServer 结构体，用于管理 DNS 服务
type DNSServer struct {
	ports []int
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
		fmt.Printf("Failed to start DNS server on port %d: %v\n", port, err)
	}
}

func getNetworkAddr(ip string) net.IP {
	ip4 := net.ParseIP(ip).To4()
	if ip4 == nil {
		return nil
	}
	netAddr := ip4.Mask(net.CIDRMask(24, 32))
	return netAddr
}

func (s *DNSServer) getForwardInfo(srcFQDN, destFQDN, inIfce string, srcIP, destIP net.IP) (newSrcFQDN, newDestFQDN string, newSrcIP, newDestIP net.IP, outIfce string) {
	// 这个函数是为路由转发程序准备的，用于获取转发信息，包括源和目标IP地址，源和目标FQDN，以及源IP地址对应的接口。
	if destFQDN == "" { //这是不支持DART的子域主机发出的报文
		// 这里的逻辑还没有全部完成。要根据目标主机是否支持DART决定转发策略
		newDestFQDN, newDestIP, _ = globalPseudoIpPool.Lookup(srcIP)
		inIfceCfg := dhcpServers[inIfce].ifConfig
		newSrcFQDN = inIfceCfg.Domain
		newSrcIP = net.IP(inIfceCfg.IPAddress[:])
		outIfce = inIfceCfg.Name
		return
	} else { //这是支持DART的主机发出的报文
		// TODO: 获取DART报头信息，并解析出DstFqdn和SrcFqdn
	}
	return srcFQDN, destFQDN, srcIP, destIP, ""
}

// ServeDNS 处理 DNS 查询
func (s *DNSServer) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	// 在DART协议中，每个子域都拥有完整的IPv4地址空间，因此这个接口可能收到来自任意地址的DNS Query报文
	// 本程序只是一个技术验证，使用轻量级的DNS库，不能返回接收到DNS Query报文的物理接口
	// 我们目前做一个简化设计，假设每个接口对应的是一个C类网段。我们比对发出报文的源地址和本机接口地址来推测接收到报文的接口
	clientIp := w.RemoteAddr().String()
	clientIp = clientIp[:strings.LastIndex(clientIp, ":")] // 去掉端口号
	clientNetAddress := getNetworkAddr(clientIp)
	//遍历globalConfig.Interfaces,比较clientNetAddress和接口的gateway地址的NetAddress。如果相同，则视为来自这个接口。如果没找到，就认为来自uplink接口
	var incomingInterface *InterfaceConfig = &globalUplinkConfig
	for i, iface := range globalConfig.Interfaces {
		if clientNetAddress.Equal(getNetworkAddr(iface.Gateway)) {
			incomingInterface = &globalConfig.Interfaces[i]
		}
	}

	queriedDomain := r.Question[0].Name

	// 找到最长匹配的接口
	outgoingInterface := s.findLongestMatchingInterface(queriedDomain)

	// 根据规则进行响应
	if incomingInterface != outgoingInterface {
		// Looking for the allocated info from dhcpServers
		if dhcpServer, ok := dhcpServers[incomingInterface.Name]; ok { // 只有downlink接口才会开启DHCP SERVER
			lease, ok := dhcpServer.leasesByIp[clientIp] // 看看查询方是不是支持DART
			if (ok && lease.DARTVersion == 0) || !ok {   // 如果有记录，且DARTversion==0,说明不支持DART；如果没记录，说明是静态配置IP的主机，默认其不支持DART
				s.respondWithPseudoIp(w, r, queriedDomain) // 分配并发送伪地址给不支持DART的本地主机
				return
			}
		}

		// 所有其他情况，均认为查询方支持DART，返回DART网关
		// 在DART协议的设计中，来自不同域的主机需要由DART网关转发报文
		// 告诉查询方：你查询的目标主机需要经过本地网关转发（返回本地网关作为CNAME）
		s.respondWithDartGateway(w, r, queriedDomain, incomingInterface)
		return
	} else {
		// 现在考虑进出是同一个接口的情况
		if outgoingInterface.Direction == "downlink" {
			s.respondWithDHCP(w, r, outgoingInterface.Name, queriedDomain)
			return
		} else {
			// 根据DNS查询机制，理论上我们并不会从上行口收到被查询的主机不属本地子域的报文
			// 万一收到了，就返回拒绝服务，即告诉查询方：这不是我们负责的范围
			s.respondWithRefusal(w, r)
			return
		}
	}
}

// findLongestMatchingInterface 找到与域名最长匹配的接口
func (s *DNSServer) findLongestMatchingInterface(domain string) *InterfaceConfig {
	var longestMatch *InterfaceConfig = &globalUplinkConfig

	for i, iface := range globalConfig.Interfaces {
		if iface.Direction == "downlink" && strings.HasSuffix(domain, iface.Domain) && len(iface.Domain) > len((longestMatch.Domain)) {
			longestMatch = &globalConfig.Interfaces[i]
		}
	}
	return longestMatch
}

func (s *DNSServer) respondWithPseudoIp(w dns.ResponseWriter, r *dns.Msg, domain string) {
	pseudoIp := globalPseudoIpPool.Allocate(domain, nil) // 当前我们还没有真实IP，暂时传入nil

	if pseudoIp == nil {
		s.respondWithServerFailure(w, r)
		return
	}

	m := new(dns.Msg)
	m.SetReply(r)
	m.Answer = append(m.Answer, &dns.A{
		Hdr: dns.RR_Header{
			// Name:   r.Question[0].Name,
			Name:   domain,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    60,
		},
		A: pseudoIp,
	})
	w.WriteMsg(m.SetReply(r))
}

func (s *DNSServer) respondWithDartGateway(w dns.ResponseWriter, r *dns.Msg, domain string, outgoingInterface *InterfaceConfig) {
	m := new(dns.Msg)
	m.SetReply(r)

	cname := &dns.CNAME{
		Hdr:    dns.RR_Header{Name: domain, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
		Target: fmt.Sprintf("dart-gateway.%s", outgoingInterface.Domain),
	}
	m.Answer = append(m.Answer, cname)

	ip := net.IP(outgoingInterface.IPAddress[:])

	a := &dns.A{
		Hdr: dns.RR_Header{Name: cname.Target, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   ip,
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
		s.respondWithRefusal(w, dnsMsg)
		return
	}

	lease, ok := dhcpServer.leasesByFQDN[domain]
	if !ok {
		s.respondWithNxdomain(w, dnsMsg)
		return
	}

	ip = lease.IP
	supportDart = lease.DARTVersion > 0

	// 构建 DNS 响应
	m := new(dns.Msg)
	m.SetReply(dnsMsg)

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
var globalPseudoIpPool *PseudoIpPool

func startDNSServerModule() {
	globalPseudoIpPool = NewPseudoIpPool(time.Hour)

	// 从全局配置中获取端口和接口信息
	ports := []int{53} // 默认使用53端口

	// 创建并启动 DNS Server
	dnsServer := NewDNSServer(ports)
	dnsServer.Start()
}

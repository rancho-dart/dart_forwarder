package main

import (
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"syscall"

	"github.com/AkihiroSuda/go-netfilter-queue"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/miekg/dns"
)

type QueueStyle int

const (
	Input QueueStyle = iota
	Forward
	Output
)

const (
	MTU = 1500
)

func (s QueueStyle) String() string {
	return [...]string{"Input", "Forward", "Output"}[s]
}

type ForwardRoutine struct {
	queue *netfilter.NFQueue
	style QueueStyle
	ifce  LinkInterface
	sock  int
}

func (fr *ForwardRoutine) Run() {
	// defer fr.queue.Close()

	switch fr.ifce.Owner.(type) {
	case *UpLinkInterface:
		logIf("info", "Uplink input processing started")
		fr.processUplink_Nat_and_Forward()
	case *DownLinkInterface:
		switch fr.style {
		case Input:
			logIf("info", "Downlink DART FORWARD processing started")
			fr.processDownlink_DartForward()
		case Forward:
			logIf("info", "Downlink NAT-DART-4 processing started")
			fr.processDownlink_Nat_4_Dart()
		}
	}
}

func (fr *ForwardRoutine) SendPacket(ifce *LinkInterface, DstIP net.IP, packet []byte) error {
	// Send packet out from interface ifce. packet shoud start from ip header
	logIf("debug2", "Send packet out of %s to %s\n", ifce.Name(), DstIP)

	// hex_dump(packet)

	addr := syscall.SockaddrInet4{}
	copy(addr.Addr[:], DstIP.To4())

	syscall.SetsockoptString(fr.sock, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, ifce.Name())
	return syscall.Sendto(fr.sock, packet, 0, &addr)
}

func (fr *ForwardRoutine) processDownlink_DartForward() {
	for packet := range fr.queue.GetPackets() {
		fr.forwardPacket("Downlink INPUT", &packet)
	}
}

func (fr *ForwardRoutine) handleExceededMTU(suggestedMTU int, ipOfLongPkt *layers.IPv4) error {
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Id:       0,
		Protocol: layers.IPProtocolICMPv4,
		SrcIP:    ipOfLongPkt.DstIP,
		DstIP:    ipOfLongPkt.SrcIP,
	}

	icmp := &layers.ICMPv4{
		TypeCode: layers.ICMPv4TypeDestinationUnreachable<<8 | layers.ICMPv4CodeFragmentationNeeded,
		Id:       0,
		Seq:      uint16(suggestedMTU),
	}

	icmp_payload := gopacket.Payload(ipOfLongPkt.Contents[:28])

	buff := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	err := gopacket.SerializeLayers(buff, opts, ip, icmp, icmp_payload)
	if err != nil {
		return err
	}

	if err := fr.SendPacket(&fr.ifce, ip.DstIP, buff.Bytes()); err != nil {
		return err
	}

	logIf("warn", "[Downlink NAT-DART-4] ICMP 'packet too big' sent to sender %s, suggest MTU %d", ipOfLongPkt.SrcIP.String(), suggestedMTU)
	return nil
}

func (fr *ForwardRoutine) processDownlink_Nat_4_Dart() {
	// 这里处理来自downlink发往伪地址的报文。因为是发往伪地址，这些报文会进入FORWARD队列。
	// 这些报文进来的时候没有DART封装，我们要根据伪地址查出目标主机的FQDN和真实IP（也没有那么真实，其实是接口所
	// 在域中的地址），给报文加上DART报头，设置IP层头的DstIP为真实IP，然后转发给目标主机。

	for packet := range fr.queue.GetPackets() {
		postTask := fr.encapsulatePacket(&packet)

		switch postTask {
		case DropPacket:
			packet.SetVerdict(netfilter.NF_DROP)
		case AcceptPacket:
			packet.SetVerdict(netfilter.NF_ACCEPT)
		default:
			logIf("error", "[Downlink NAT-DART-4] Unknown post task: %v", postTask)
			packet.SetVerdict(netfilter.NF_ACCEPT) // 默认放行
		}
	}
}

func trimIpSuffix(s string) string {
	parts := strings.Split(s, ".")
	lastPart := &parts[len(parts)-1]
	ip := make(net.IP, 4)
	n, err := fmt.Sscanf(*lastPart, "[%d-%d-%d-%d]", &ip[0], &ip[1], &ip[2], &ip[3])
	if err == nil && n == 4 {
		*lastPart = ""
		return strings.Join(parts, ".")
	}
	return s
}

type PostTask int

const (
	DropPacket PostTask = iota // 0
	AcceptPacket
)

func (fr *ForwardRoutine) forwardPacket(pktStyle string, packet *netfilter.NFPacket) {
	ipLayer := packet.Packet.Layer(layers.LayerTypeIPv4)
	postTask := AcceptPacket

	if ipLayer != nil {
		ip, ok := ipLayer.(*layers.IPv4)
		if ok {
			logIf("debug2", "[%s] Received packet: %s -> %s\n", pktStyle, ip.SrcIP, ip.DstIP)

			if ip.Protocol == layers.IPProtocolUDP {
				udpLayer := packet.Packet.Layer(layers.LayerTypeUDP)
				if udpLayer != nil {
					udp, ok := udpLayer.(*layers.UDP)
					if ok {
						logIf("debug2", "[%s] Received udp packet: %s -> %s\n", pktStyle, udp.SrcPort, udp.DstPort)
						if udp.DstPort == DARTPort || udp.SrcPort >= 1024 {
							dartLayer := packet.Packet.Layer(LayerTypeDART)
							if dartLayer != nil {
								dart, ok := dartLayer.(*DART)
								if ok {
									postTask = fr.forwardDartPacket(pktStyle, ip, udp, dart)
								}
							}
						}
					}
				}
			}
		}
	}

	switch postTask {
	case DropPacket:
		packet.SetVerdict(netfilter.NF_DROP)
	case AcceptPacket:
		packet.SetVerdict(netfilter.NF_ACCEPT)
	default:
		logIf("error", "[%s] Unknown post task: %v", pktStyle, postTask)
		packet.SetVerdict(netfilter.NF_ACCEPT) // 默认放行
	}
}

func (fr *ForwardRoutine) encapsulatePacket(packet *netfilter.NFPacket) PostTask {
	ipLayer := packet.Packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return AcceptPacket
	}

	ip, ok := ipLayer.(*layers.IPv4)
	if !ok {
		return AcceptPacket // 如果不是IPv4层，直接放行报文
	}

	logIf("debug2", "[Downlink NAT-DART-4] Received packet: %s -> %s\n", ip.SrcIP, ip.DstIP)
	if !PSEUDO_POOL.isPseudoIP(ip.DstIP) {
		return AcceptPacket // 如果目标IP不是伪地址，直接放行报文
	}

	// 这里获取伪地址对应的IP和FQDN。
	// 在前面的DNS LOOKUP中，我们已经在上联口的DNS SERVER上解析过域名（FQDN）对应的IP并据此分配了伪地址
	// 所以如果表中能查到，目标域名和其在上联口所在域中的IP是都可以直接得到
	DstFqdn, DstIP, DstUdpPort, ok := PSEUDO_POOL.Lookup(ip.DstIP)
	if !ok {
		logIf("error", "[Downlink NAT-DART-4] DstIP %s not found in pseudo ip pool\n", ip.DstIP)
		return DropPacket
	}

	// 根据目标 FQDN 找出应该转发的端口
	outLI := DNS_SERVER.getOutboundIfce(DstFqdn)
	if outLI == nil {
		logIf("error", "[Downlink NAT-DART-4] No route to forward packet to %s \n", DstFqdn)
		return DropPacket
	}

	// 现在我们再来确定源FQDN
	inLI, ok := fr.ifce.Owner.(*DownLinkInterface)
	if !ok {
		// 除非设置错了队列，否则只会在下联口收到报文
		logIf("error", "[Downlink NAT-DART-4] Packet enters from non-downlink interface\n")
		return AcceptPacket
	}

	server, ok := DHCP_SERVERS[inLI.Name]
	if !ok || server == nil {
		logIf("error", "[Downlink NAT-DART-4] No DHCP server running on interface %s\n", inLI.Name)
		return DropPacket // 如果没有DHCP服务器，无法获取源FQDN
	}

	var SrcFqdn string
	lease, ok := server.leasesByIp[ip.SrcIP.String()]
	if !ok {
		// 源主机的IP不是通过DHCP获得的（DHCP/DNS系统中没有此主机的记录），我们用其IP构筑其DART的源地址
		// 对方如果是直接接入根域的，那么其实用不上这个地址，因为IP层的源地址就足够正确返回报文了
		// 这是为对方主机位于派生出的子域准备的
		SrcFqdn = fmt.Sprintf("[%d-%d-%d-%d].%s", ip.SrcIP[0], ip.SrcIP[1], ip.SrcIP[2], ip.SrcIP[3], inLI.Domain)
	} else {
		SrcFqdn = lease.FQDN
	}

	// 我们已经得到了源FQDN，但对方主机能不能正常解析这个FQDN还有依赖条件：
	// 只有在父域的DNS系统中注册过的域名才能被父域的DNS解析，外面的主机才能查询到这个域名对应的IP
	// 源地址设置为本地域中的主机才能意义
	if !inLI.RegistedInUplinkDNS {
		// 如果子域的域名没有在父域的DNS系统中注册过，那么只有一种可能：
		// 这台设备直接（或者通过NAT）连接到公网（中间没有其他DART网关），那么这时候我们就需要将公网地址嵌入DART的源地址，以便报文接收方知道报文回应给谁
		// 接收方的响应报文在进入根域时DART网关会从目标地址中拆解出IP并填入IP层的目标地址
		_ip := CONFIG.Uplink.PublicIP()
		SrcFqdn = fmt.Sprintf("%s[%d-%d-%d-%d]", SrcFqdn, _ip[0], _ip[1], _ip[2], _ip[3])
	}

	DstFqdn = strings.TrimSuffix(DstFqdn, ".")

	dart := &DART{
		Version:    1,
		Protocol:   ip.Protocol,
		DstFqdnLen: uint8(len(DstFqdn)),
		SrcFqdnLen: uint8(len(SrcFqdn)),
		DstFqdn:    []byte(DstFqdn),
		SrcFqdn:    []byte(SrcFqdn),
		Payload:    ip.Payload,
	}

	udp := &layers.UDP{
		SrcPort: layers.UDPPort(DARTPort),
		DstPort: layers.UDPPort(DstUdpPort),
		Length:  uint16(len(dart.Payload)) + uint16(dart.HeaderLen()) + 8, // UDP 头长度为 8 字节
	}

	newIp := *ip
	newIp.SrcIP = outLI.Addr() // CONFIG.Uplink.ipNet.IP
	newIp.DstIP = DstIP
	newIp.Protocol = layers.IPProtocolUDP

	udp.SetNetworkLayerForChecksum(&newIp)

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	err := gopacket.SerializeLayers(buffer, opts, &newIp, udp, dart, gopacket.Payload(dart.Payload))

	if err != nil {
		logIf("error", "[Downlink NAT-DART-4] Failed to serialize packet: %v", err)
		return DropPacket
	}

	packetLen := len(buffer.Bytes())

	if packetLen > MTU {
		suggestedMTU := MTU - int(dart.HeaderLen()+8) // UDP头长度为8字节
		err := fr.handleExceededMTU(suggestedMTU, ip)
		if err != nil {
			logIf("error", "[Downlink NAT-DART-4] Failed to handle exceeded MTU: %v", err)
		}
		return DropPacket // 丢弃超长包
	}

	if err := fr.SendPacket(outLI, newIp.DstIP, buffer.Bytes()); err != nil {
		logIf("error", "[Downlink NAT-DART-4] Failed to send packet: %v", err)
	}

	return DropPacket
}

func (fr *ForwardRoutine) forwardDartPacket(pktStyle string, ip *layers.IPv4, udp *layers.UDP, dart *DART) PostTask {
	// 目的主机有两种可能：支持DART协议，或者不支持
	// 如果支持，那么保持DART报头不变，IP报头中的源地址换成本机转发接口IP，目标地址换成本地子域中的IP
	// 如果不支持，那么删除DART报头，查找DART源地址对应的伪地址（如不存在就分配）并作为IP报头源地址，目标地址换成本地子域中的IP

	logIf("debug2", "[%s] Received dart packet: %s -> %s\n", pktStyle, dart.SrcFqdn, dart.DstFqdn)

	dstFqdn := string(dart.DstFqdn)

	switch inLI := fr.ifce.Owner.(type) {
	case *DownLinkInterface:
		// Do nothing
	case *UpLinkInterface:
		// Now the dstFqdn may looks like c1.sh.cn.[192-168-2.100]
		// 如果我们收到这样的报文，则说明我方发送的报文在SrcFqdn中嵌入了IP，对方将其作为DstFqdn回复过来了。我们要先删除这一部分才好判断往哪里转发。
		if inLI.inRootDomain {
			dstFqdn = trimIpSuffix(dstFqdn)
		}
	default:
		logIf("error", "[%s] Unknown interface type: %T", pktStyle, fr.ifce.Owner)
		return DropPacket
	}

	dstFqdn = dns.Fqdn(dstFqdn)

	// 我们先试着从DHCP分配记录里寻找域名对应的IP
	outboundIfce := DNS_SERVER.getOutboundIfce(dstFqdn)
	if outboundIfce == nil {
		// 没找到合适的转发接口。正常不会，因为上联口是默认接口
		return DropPacket
	}

	var dstIP net.IP
	var forwardAsDart bool

	switch outLI := outboundIfce.Owner.(type) {
	case *UpLinkInterface:
		logIf("debug2", "[%s] Forwarding dart packet to uplink interface %s\n", pktStyle, outboundIfce.Name())

		forwardAsDart = true // 上联口的DART网关总是支持DART协议

		IP, supportDart := outLI.resolveWithCache(dstFqdn)
		if IP == nil {
			logIf("error", "[%s] Destination %s does not exist, dropping packet", pktStyle, dstFqdn)
			return DropPacket
		}

		if !supportDart {
			// 因为是向上联口转发，目标必须支持DART协议
			logIf("error", "[%s] Destination %s does not support DART, dropping packet", pktStyle, dstFqdn)
			return DropPacket
		}

		dstIP = IP
		forwardAsDart = true
		logIf("debug2", "[%s] forwarding DART packet heading %s to %s", pktStyle, dstFqdn, IP)

	case *DownLinkInterface:
		logIf("debug2", "[%s] Forwarding DART packet to downlink interface %s\n", pktStyle, outboundIfce.Name())

		level1SubDomain, isSubDomain := findSubDomainUnder(dstFqdn, outLI.Domain)
		if !isSubDomain {
			logIf("error", "[%s] Destination %s is not in the subdomain %s, dropping packet", pktStyle, dstFqdn, outLI.Domain)
			return DropPacket
		}

		lease := DNS_SERVER.getDhcpLeaseByFqdn(outboundIfce.Name(), level1SubDomain)
		if lease != nil {
			dstIP = lease.IP
			if lease.DARTVersion > 0 {
				forwardAsDart = true // 如果是DART-Ready由应当转发DART报文
			} else if lease.Delegated {
				if len(lease.FQDN) < len(dstFqdn) {
					forwardAsDart = true // 如果是发往子域的记录，则应当转发DART报文。如果是发给DART网关本身，则应当转发纯IP报文
				}
			}
		}

		if dstIP == nil {
			logIf("error", "[%s] Destination %s does not exist, dropping packet", pktStyle, dstFqdn)
			return DropPacket
		}
	default:
		logIf("error", "unknown outbound interface type: %v", outboundIfce)
		return DropPacket
	}

	buff := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	var err error

	if forwardAsDart {
		pktStyle = "DART FORWARD"

		// 更新 IP 地址
		ip.SrcIP = outboundIfce.Addr()
		ip.DstIP = dstIP

		// 重新构造 UDP 层，为计算校验和准备
		udp.SetNetworkLayerForChecksum(ip)

		// 重新序列化 IP + UDP + DART + 原始 Payload
		err = gopacket.SerializeLayers(buff, opts,
			ip, udp, dart, gopacket.Payload(dart.Payload))

		logIf("debug2", "[%s] Forward packet from %s(%s) to %s(%s)", pktStyle, dart.SrcFqdn, ip.SrcIP, dstFqdn, dstIP)

	} else { // Convert to plain IPv4 packet and forward
		pktStyle = "NAT-DART-4"

		// 删除 DART 报头和UDP报头
		ip.DstIP = dstIP
		ip.SrcIP = PSEUDO_POOL.FindOrAllocate(string(dart.SrcFqdn), ip.SrcIP, uint16(udp.SrcPort))
		ip.Protocol = dart.Protocol

		// 如果DART的Payload是TCP/UDP，因为其Checksum计算包含伪头部，需要更新其Checksum
		packetData := gopacket.NewPacket(dart.Payload, dart.Protocol.LayerType(), gopacket.Default)

		// 重新序列化 IP + 原始 Payload
		switch dart.Protocol {
		case layers.IPProtocolTCP:
			if tcpLayer := packetData.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				tcp := tcpLayer.(*layers.TCP)
				tcp.SetNetworkLayerForChecksum(ip)
				err = gopacket.SerializeLayers(buff, opts,
					ip, tcp, gopacket.Payload(tcp.Payload))
			}
		case layers.IPProtocolUDP:
			if udpLayer := packetData.Layer(layers.LayerTypeUDP); udpLayer != nil {
				udp := udpLayer.(*layers.UDP)
				udp.SetNetworkLayerForChecksum(ip)
				err = gopacket.SerializeLayers(buff, opts,
					ip, udp, gopacket.Payload(udp.Payload))
			}
		case layers.IPProtocolICMPv4:
			if icmpLayer := packetData.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
				icmp := icmpLayer.(*layers.ICMPv4)
				err = gopacket.SerializeLayers(buff, opts,
					ip, icmp, gopacket.Payload(icmp.Payload)) // 此函数会重新计算icmp的checksum
			}
		default:
			err = fmt.Errorf("[%s] Unsupported protocol in dart payload", pktStyle)
		}

		logIf("debug2", "[%s] Forward packet to %s", pktStyle, dstIP)
	}

	if err != nil {
		logIf("error", "[%s] Failed to serialize packet: %v", pktStyle, err)
		return DropPacket
	}

	// hex_dump(buffer.Bytes())

	// 从 outIfce 指定的端口发出报文
	if err := fr.SendPacket(outboundIfce, dstIP, buff.Bytes()); err != nil {
		logIf("error", "[%s] Failed to send packet: %v", pktStyle, err)
	}

	// 报文已经从另一个端口转发了，当前报文直接 Drop
	return DropPacket
}

func (fr *ForwardRoutine) processUplink_Nat_and_Forward() {
	// 这里处理来自CONFIG.Uplink的报文
	// 从这个接口进来的报文，只有DART封装的需要转发，其他的都透明通过
	pktStyle := "Uplink INPUT"

	for packet := range fr.queue.GetPackets() {
		fr.forwardPacket(pktStyle, &packet)
	}
}

func Hex_dump(data []byte) {
	for i, b := range data {
		if i%16 == 0 {
			if i != 0 {
				// 打印当前行的可显示字符
				fmt.Printf("  |")
				for j := i - 16; j < i; j++ {
					if data[j] >= 32 && data[j] <= 126 {
						fmt.Printf("%c", data[j])
					} else {
						fmt.Printf(".")
					}
				}
				fmt.Printf("| ")
			}
			fmt.Printf("\n%04x: ", i)
		}
		fmt.Printf("%02x ", b)
	}

	// 处理最后一行未对齐的情况
	if len(data)%16 != 0 {
		spaces := (16 - len(data)%16) * 3
		fmt.Printf("%*s", spaces, "")

		fmt.Printf("  |")
		for j := len(data) - len(data)%16; j < len(data); j++ {
			if data[j] >= 32 && data[j] <= 126 {
				fmt.Printf("%c", data[j])
			} else {
				fmt.Printf(".")
			}
		}
		fmt.Printf("|")
	}
	fmt.Println()
}

func createAndStartQueue(queueNo uint16, ifce LinkInterface, style QueueStyle) {
	queue, err := netfilter.NewNFQueue(queueNo, 1000, netfilter.NF_DEFAULT_PACKET_SIZE)
	if err != nil {
		log.Fatalf("error creating queue: %v", err)
	}

	sock, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW) // 这种方式创建的sock只能发送从IP头开始的数据，不能指定接口发送。严格来说这种方式不符合DART的设计。但是用于家庭网关或者中小企业网关场景，也差强人意了。我们省点事。
	if err != nil {
		log.Fatalf("Failed to create raw socket: %v", err)
	}

	err = syscall.SetsockoptInt(sock, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1) // 设置 IP_HDRINCL，表示我们自己构造 IP 头
	if err != nil {
		log.Fatalf("Failed to set IP_HDRINCL: %v", err)
	}

	forwardRouting := ForwardRoutine{
		queue: queue,
		style: style,
		ifce:  ifce,
		sock:  sock,
	}
	go forwardRouting.Run()
}

func EnableNAT44(rm *RuleManager) {
	// Add NAT44 rules
	rm.AddRule("nat", "POSTROUTING", []string{"-p", "udp", "--sport", "55847", "-j", "RETURN"})
	rm.AddRule("nat", "POSTROUTING", []string{"-p", "udp", "--dport", "55847", "-j", "RETURN"})

	outIfce := CONFIG.Uplink.Name
	for I, DownLink := range CONFIG.Downlinks {
		if DownLink.Name == CONFIG.Uplink.Name {
			logIf("warn", "Router-on-a-stick is enabled on interface %s, so NAT44 is not enabled.", DownLink.Name)
			continue
		}
		// 检查下联口的地址是否是私网地址
		if isPrivateAddr(DownLink.ipNet.IP) {
			private_network := DownLink.ipNet.String()
			rm.AddRule("nat", "POSTROUTING", []string{"-o", outIfce, "-s", private_network, "-j", "MASQUERADE"})

			// 默认ACCEPT的情况下，不加下面的两条规则，也能正常工作。加上这两条规则，不依赖默认配置
			rm.AddRule("filter", "FORWARD", []string{"-i", DownLink.Name, "-o", outIfce, "-s", private_network, "!", "-d", PSEUDO_IP_POOL, "-m", "conntrack", "--ctstate", "NEW,ESTABLISHED,RELATED", "-j", "ACCEPT"})
			rm.AddRule("filter", "FORWARD", []string{"-o", DownLink.Name, "-i", outIfce, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"})

			logIf("info", "Since interface %s has private address, NAT44 is enabled on it.", DownLink.Name)
			CONFIG.Downlinks[I].NAT44enabled = true
		}
	}
}

func startForwardModule() {

	rm := NewRuleManager()
	go rm.CleanupOnSignal(&WG)

	logIf("info", "Creating queues & iptable rules to capture packets...")

	EnableNAT44(rm)

	// Add NFQUEUE rules
	var queueNo uint16 = 0

	createAndStartQueue(queueNo, CONFIG.Uplink.LinkInterface, Input)
	if err := rm.AddRule("filter", "INPUT", []string{"-i", CONFIG.Uplink.Name, "-p", "udp", "--dport", "55847", "-j", "NFQUEUE", "--queue-num", strconv.Itoa(int(queueNo))}); err != nil {
		log.Fatalf("Failed to set iptables rule for CONFIG.Uplink input: %v", err)
	}
	queueNo++

	for _, DownLink := range CONFIG.Downlinks {
		createAndStartQueue(queueNo, DownLink.LinkInterface, Forward)
		if err := rm.AddRule("filter", "FORWARD", []string{"-i", DownLink.Name, "-j", "NFQUEUE", "--queue-num", strconv.Itoa(int(queueNo))}); err != nil {
			log.Fatalf("Failed to set iptables rule for Downlink NAT-DART-4: %v", err)
		}
		queueNo++

		if DownLink.Name == CONFIG.Uplink.Name {
			logIf("warn", "Router-on-a-stick is enabled on interface %s, so DART packets forwarding is disabled.", DownLink.Name)
			continue
		}

		createAndStartQueue(queueNo, DownLink.LinkInterface, Input)
		if err := rm.AddRule("filter", "INPUT", []string{"-i", DownLink.Name, "-p", "udp", "--dport", "55847", "-j", "NFQUEUE", "--queue-num", strconv.Itoa(int(queueNo))}); err != nil {
			log.Fatalf("Failed to set iptables rule for Downlink DART FORWARD: %v", err)
		}
		queueNo++
	}

	logIf("info", "Forward module started successfully on NFQUEUE...")

	select {}
}

// isPrivateAddr 检查IP地址是否是私网地址
func isPrivateAddr(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		// 10.0.0.0/8
		if ip4[0] == 10 {
			return true
		}
		// 172.16.0.0/12
		if ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
			return true
		}
		// 192.168.0.0/16
		if ip4[0] == 192 && ip4[1] == 168 {
			return true
		}
	}
	return false
}

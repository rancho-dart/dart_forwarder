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
		log.Println("uplink input processing start")
		fr.processUplinkInputPackets()
		log.Println("uplink forward processing end")
	case *DownLinkInterface:
		switch fr.style {
		case Input:
			log.Println("Downlink DART FORWARD processing start")
			fr.processDownlinkInputPackets()
			log.Println("Downlink DART FORWARD processing end")
		case Forward:
			log.Println("Downlink NAT-4-DART processing start")
			fr.processDownlinkForwardPackets()
			log.Println("Downlink NAT-4-DART processing end")
		}
	}
}

func (fr *ForwardRoutine) SendPacket(ifce *LinkInterface, DstIP net.IP, packet []byte) error {
	// Send packet out from interface ifce. packet shoud start from ip header
	log.Printf("Send packet out of %s to %s\n", ifce.Name(), DstIP)

	// hex_dump(packet)

	addr := syscall.SockaddrInet4{}
	copy(addr.Addr[:], DstIP.To4())

	syscall.SetsockoptString(fr.sock, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, ifce.Name())
	return syscall.Sendto(fr.sock, packet, 0, &addr)
}

func (fr *ForwardRoutine) processDownlinkInputPackets() {
	for packet := range fr.queue.GetPackets() {
		ipLayer := packet.Packet.Layer(layers.LayerTypeIPv4)
		if ipLayer != nil {
			ip := ipLayer.(*layers.IPv4)
			log.Printf("[Downlink DART FORWARD] Received packet: %s -> %s\n", ip.SrcIP, ip.DstIP)

			// 检查是否为 UDP 报文且目标端口为 DART 端口
			if ip.Protocol == layers.IPProtocolUDP {
				udpLayer := packet.Packet.Layer(layers.LayerTypeUDP)
				if udpLayer != nil {
					udp := udpLayer.(*layers.UDP)
					if udp.DstPort == DARTPort {
						// 解析 DART 头
						dartLayer := packet.Packet.Layer(LayerTypeDART)
						if dartLayer != nil {
							dart := dartLayer.(*DART)
							log.Printf("[Downlink DART FORWARD] Received DART packet: %s -> %s\n", dart.SrcFqdn, dart.DstFqdn)

							// 调用 dnsServer.resolve() 获取目标 IP
							outIfce := CONFIG.Uplink
							destIp, suppDart := outIfce.resolveA(string(dart.DstFqdn))
							if destIp == nil {
								// 没有找到目标 IP，丢弃报文
								log.Printf("[Downlink DART FORWARD] Failed to resolve destination IP for %s\n", string(dart.DstFqdn))
								packet.SetVerdict(netfilter.NF_DROP)
								continue
							}
							if !suppDart {
								// 目标不支持 DART，丢弃报文
								log.Printf("[Downlink DART FORWARD] Destination %s does not support DART\n", string(dart.DstFqdn))
								packet.SetVerdict(netfilter.NF_DROP)
								continue
							}

							// 修改 IP 报头的目标地址和源地址
							ip.DstIP = destIp
							ip.SrcIP = outIfce.ipNet.IP
							udp.SetNetworkLayerForChecksum(ip)

							// 重新序列化 IP + UDP + DART + 原始 Payload
							buffer := gopacket.NewSerializeBuffer()
							opts := gopacket.SerializeOptions{
								FixLengths:       true,
								ComputeChecksums: true,
							}
							err := gopacket.SerializeLayers(buffer, opts, ip, udp, dart, gopacket.Payload(dart.Payload))
							if err != nil {
								log.Printf("[Downlink DART FORWARD] Failed to serialize packet: %v", err)
								packet.SetVerdict(netfilter.NF_DROP)
								continue
							}

							// 从上行接口发出修改后的报文
							if err := fr.SendPacket(&outIfce.LinkInterface, destIp, buffer.Bytes()); err != nil {
								log.Printf("[Downlink DART FORWARD] Failed to send packet: %v", err)
							}

							// 丢弃原始报文
							packet.SetVerdict(netfilter.NF_DROP)
							continue
						}
					}
				}
			}
		}

		// 默认放行非 DART 报文
		packet.SetVerdict(netfilter.NF_ACCEPT)
	}
}

func (fr *ForwardRoutine) handleExceededMTU(packetLen int, ipOfLongPkt *layers.IPv4) error {
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Id:       0,
		Protocol: layers.IPProtocolICMPv4,
		SrcIP:    ipOfLongPkt.DstIP,
		DstIP:    ipOfLongPkt.SrcIP,
	}
	suggestMTU := MTU - (packetLen - MTU)
	icmp := &layers.ICMPv4{
		TypeCode: layers.ICMPv4TypeDestinationUnreachable<<8 | layers.ICMPv4CodeFragmentationNeeded,
		Id:       0,
		Seq:      uint16(suggestMTU),
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

	log.Printf("[Downlink NAT-4-DART] ICMP 'packet too long' replied to sender. Suggested MTU: %d", suggestMTU)
	return nil
}
func (fr *ForwardRoutine) processDownlinkForwardPackets() {
	// 这里处理来自downlink发往伪地址的报文。因为是发往伪地址，这些报文会进入FORWARD队列。报文的去向，必须是CONFIG.Uplink方向（目前我们
	// 只实现这个）。这些报文进来的时候没有DART封装，我们要根据伪地址查出目标主机的FQDN和真实IP（也没有那么真实，其实是上联接口所
	// 在域中的地址），给报文加上DART报头，设置IP层头的DstIP为真实IP，然后转发给目标主机。
NextPacket:
	for packet := range fr.queue.GetPackets() {
		for range 1 {
			ipLayer := packet.Packet.Layer(layers.LayerTypeIPv4)
			if ipLayer == nil {
				break
			}

			ip := ipLayer.(*layers.IPv4)
			if ip == nil {
				break
			}
			log.Printf("[Downlink NAT-4-DART] Received packet: %s -> %s\n", ip.SrcIP, ip.DstIP)
			// check whether the destip is pseudo ip
			if !PSEUDO_POOL.isPseudoIP(ip.DstIP) {
				break
			}

			// 这里获取伪地址对应的IP和FQDN。
			// 在前面的DNS LOOKUP中，我们已经在上联口的DNS SERVER上解析过域名（FQDN）对应的IP并据此分配了伪地址
			// 所以如果表中能查到，目标域名和其在上联口所在域中的IP是都可以直接得到
			DstFqdn, DstIP, DstUdpPort, ok := PSEUDO_POOL.Lookup(ip.DstIP)
			if !ok {
				log.Printf("[Downlink NAT-4-DART] DstIP %s not found in pseudo ip pool\n", ip.DstIP)
				packet.SetVerdict(netfilter.NF_DROP)
				continue NextPacket
			}

			DstFqdn = strings.TrimSuffix(DstFqdn, ".")

			// 现在我们再来确定源FQDN
			inLI := fr.ifce.Owner.(*DownLinkInterface) // 报文肯定是下联口接收到的
			server, ok := DHCP_SERVERS[inLI.Name]
			if !ok || server == nil {
				log.Printf("[Downlink NAT-4-DART] no DHCP server for interface %s\n", inLI.Name)
				packet.SetVerdict(netfilter.NF_DROP)
				continue NextPacket
			}

			lease, ok := server.leasesByIp[ip.SrcIP.String()]
			if !ok {
				log.Printf("[Downlink NAT-4-DART] no lease for IP %s\n", ip.SrcIP)
				packet.SetVerdict(netfilter.NF_DROP)
				continue NextPacket
			}

			SrcFqdn := lease.FQDN

			// 我们已经得到了源FQDN，但对方主机能不能正常解析这个FQDN还有依赖条件：
			// 只有在上联口的DNS系统中注册过的域名才能被上联口上的DNS正常解析，外面的主机才能查询到这个域名对应的IP
			// 源地址设置为本地域中的主机才能意义
			if !inLI.RegistedInUplinkDNS {
				// 如果下联口的域名没有在上联口的DNS系统中注册过，那么只有一种可能：
				// 这台设备直接（或者通过NAT）连接到公网（中间没有其他DART网关），那么这时候我们就需要将公网地址嵌入DART的源地址，以便报文接收方知道报文回应给谁
				_ip := CONFIG.Uplink.PublicIP()
				SrcFqdn = fmt.Sprintf("%s[%d-%d-%d-%d]", SrcFqdn, _ip[0], _ip[1], _ip[2], _ip[3])
			}

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
			newIp.SrcIP = CONFIG.Uplink.ipNet.IP
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
				log.Printf("[Downlink NAT-4-DART] Failed to serialize packet: %v", err)
				packet.SetVerdict(netfilter.NF_DROP)
				continue NextPacket
			}

			packetLen := len(buffer.Bytes())

			if packetLen > MTU {
				err := fr.handleExceededMTU(packetLen, ip)
				if err != nil {
					log.Printf("[Downlink NAT-4-DART] Failed to handle exceeded MTU: %v", err)
				}
				packet.SetVerdict(netfilter.NF_DROP)
				continue NextPacket
			}

			// hex_dump(buffer.Bytes())
			if err := fr.SendPacket(&CONFIG.Uplink.LinkInterface, newIp.DstIP, buffer.Bytes()); err != nil {
				log.Printf("[Downlink NAT-4-DART] Failed to send packet: %v", err)
			}

			packet.SetVerdict(netfilter.NF_DROP)
			continue NextPacket
		} // Pseudo loop

		// 上面的伪循环如果Break出来，就放行当前报文
		packet.SetVerdict(netfilter.NF_ACCEPT)
	} // Packet loop
}

func trimIpSuffix(s string) string {
	if i := strings.Index(s, "["); i != -1 {
		return s[:i]
	}
	return s
}
func (fr *ForwardRoutine) processUplinkInputPackets() {
	// 这里处理来自CONFIG.Uplink的报文
	// 从这个接口进来的报文，只有DART封装的需要转发，其他的都透明通过
	// 报文的去向，必须是downlink方向
	// 目的主机有两种可能：支持DART协议，或者不支持
	// 如果支持，那么保持DART报头不变，IP报头中的源地址换成本机转发接口IP，目标地址换成本地子域中的IP
	// 如果不支持，那么删除DART报头，查找DART源地址对应的伪地址（如不存在就分配）并作为IP报头源地址，目标地址换成本地子域中的IP
NextPacket:
	for packet := range fr.queue.GetPackets() {
		for range 1 {
			// Pseudo loop. if any packet which shoud pass though, 'break' can jump to ACCEPT directly.
			// Otherwise SetVerdictWithPacket or Drop, and then continue NextPacket
			ipLayer := packet.Packet.Layer(layers.LayerTypeIPv4)
			if ipLayer == nil {
				break // Break from the inner for-loop, let the packet go through
			}
			pktStyle := "Uplink INPUT"
			ip := ipLayer.(*layers.IPv4)
			log.Printf("[%s] Received packet: %s -> %s\n", pktStyle, ip.SrcIP, ip.DstIP)

			// check whether it is udp
			if ip.Protocol != layers.IPProtocolUDP {
				break
			}

			udpLayer := packet.Packet.Layer(layers.LayerTypeUDP)
			if udpLayer == nil {
				break
			}

			udp := udpLayer.(*layers.UDP)
			log.Printf("[%s] Received udp packet: %s -> %s\n", pktStyle, udp.SrcPort, udp.DstPort)
			if udp.DstPort != DARTPort {
				break
			}

			dartLayer := packet.Packet.Layer(LayerTypeDART)
			if dartLayer == nil {
				break
			}

			dart := dartLayer.(*DART)
			log.Printf("[%s] Received dart packet: %s -> %s\n", pktStyle, dart.SrcFqdn, dart.DstFqdn)

			// Now the dstFqdn may looks like c1.sh.cn.[192-168-2.100]
			// We need to check it. If the last part is a ip address, we need to remove it.
			dstFqdn := dns.Fqdn(trimIpSuffix(string(dart.DstFqdn)))
			srcFqdn := dns.Fqdn(trimIpSuffix(string(dart.SrcFqdn)))

			outIfce, dstIp, supportDart := DNS_SERVER.lookup(dstFqdn)
			if outIfce == nil || dstIp == nil {
				// 没找到合适的转发接口或目标IP
				packet.SetVerdict(netfilter.NF_DROP)
				continue NextPacket
			}

			buff := gopacket.NewSerializeBuffer()
			opts := gopacket.SerializeOptions{
				FixLengths:       true,
				ComputeChecksums: true,
			}

			var err error
			if supportDart {
				pktStyle = "Uplink DART FORWARD"
				// 更新 IP 地址
				ip.SrcIP = outIfce.Addr()
				ip.DstIP = dstIp

				// 重新构造 UDP 层，为计算校验和准备
				udp.SetNetworkLayerForChecksum(ip)

				// 重新序列化 IP + UDP + DART + 原始 Payload

				err = gopacket.SerializeLayers(buff, opts,
					ip, udp, dart, gopacket.Payload(dart.Payload))

				log.Printf("[%s] Forward packet to %s(%s)", pktStyle, dstFqdn, dstIp)
			} else { // dest host doesn't support DART
				pktStyle = "Uplink NAT-DART-4"
				// 删除 DART 报头和UDP报头
				ip.DstIP = dstIp
				ip.SrcIP = PSEUDO_POOL.FindOrAllocate(srcFqdn, ip.SrcIP, uint16(udp.SrcPort))
				// ip.SrcIP = outIfce.IPAddress[:]
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
					err = fmt.Errorf("[%s] unsupported protocol in dart payload", pktStyle)
				}
				log.Printf("[%s] forward packet to %s", pktStyle, dstIp)
			} // dest host doesn't support DART. logic ends here

			if err != nil {
				log.Printf("[%s] Failed to serialize packet: %v", pktStyle, err)
				packet.SetVerdict(netfilter.NF_DROP)
				continue NextPacket
			}

			// hex_dump(buffer.Bytes())
			// 从 outIfce 指定的端口发出报文
			if err := fr.SendPacket(outIfce, dstIp, buff.Bytes()); err != nil {
				log.Printf("[%s] Failed to send packet: %v", pktStyle, err)
			}

			// 报文已经改造后从另一个端口发出了。当前报文直接 Drop
			packet.SetVerdict(netfilter.NF_DROP)
			continue NextPacket
		} // inner for loop

		// 一定要给出 verdict，不然内核一直等着
		packet.SetVerdict(netfilter.NF_ACCEPT)
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

func startForwardModule() {

	rm := NewRuleManager()
	go rm.CleanupOnSignal()

	log.Println("Creating queues & iptable rules to capture packets...")

	// Add NAT44 rules
	rm.AddRule("nat", "POSTROUTING", []string{"-p", "udp", "--sport", "55847", "-j", "RETURN"})
	rm.AddRule("nat", "POSTROUTING", []string{"-p", "udp", "--dport", "55847", "-j", "RETURN"})

	outIfce := CONFIG.Uplink.LinkInterface.Name()
	for _, inLI := range CONFIG.Downlinks {
		// 检查下联口的地址是否是私网地址
		if isPrivateAddr(inLI.ipNet.IP) {
			private_network := inLI.ipNet.String()
			rm.AddRule("nat", "POSTROUTING", []string{"-o", outIfce, "-s", private_network, "-j", "MASQUERADE"})

			// 默认ACCEPT的情况下，不加下面的两条规则，也能正常工作。加上这两条规则，不依赖默认配置
			rm.AddRule("filter", "FORWARD", []string{"-i", inLI.Name, "-o", outIfce, "-s", private_network, "!", "-d", PSEUDO_IP_POOL, "-m", "conntrack", "--ctstate", "NEW,ESTABLISHED,RELATED", "-j", "ACCEPT"})
			rm.AddRule("filter", "FORWARD", []string{"-o", inLI.Name, "-i", outIfce, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"})
		}
	}

	// Add NFQUEUE rules
	var queueNo uint16 = 0

	createAndStartQueue(queueNo, CONFIG.Uplink.LinkInterface, Input)
	if err := rm.AddRule("filter", "INPUT", []string{"-i", CONFIG.Uplink.Name, "-p", "udp", "--dport", "55847", "-j", "NFQUEUE", "--queue-num", strconv.Itoa(int(queueNo))}); err != nil {
		log.Fatalf("Failed to set iptables rule for CONFIG.Uplink input: %v", err)
	}
	queueNo++

	for _, ifce := range CONFIG.Downlinks {
		createAndStartQueue(queueNo, ifce.LinkInterface, Forward)
		if err := rm.AddRule("filter", "FORWARD", []string{"-i", ifce.Name, "-j", "NFQUEUE", "--queue-num", strconv.Itoa(int(queueNo))}); err != nil {
			log.Fatalf("Failed to set iptables rule for Downlink NAT-4-DART: %v", err)
		}
		queueNo++

		createAndStartQueue(queueNo, ifce.LinkInterface, Input)
		if err := rm.AddRule("filter", "INPUT", []string{"-i", ifce.Name, "-p", "udp", "--dport", "55847", "-j", "NFQUEUE", "--queue-num", strconv.Itoa(int(queueNo))}); err != nil {
			log.Fatalf("Failed to set iptables rule for Downlink DART FORWARD: %v", err)
		}
		queueNo++
	}

	log.Println("Forward module started successfully on NFQUEUE...")

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

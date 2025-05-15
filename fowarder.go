package main

import (
	"errors"
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
			log.Println("downlink input processing start")
			fr.processDownlinkInputPackets()
			log.Println("downlink input processing end")
		case Forward:
			log.Println("downlink forward processing start")
			fr.processDownlinkForwardPackets()
			log.Println("downlink forward processing end")
		}
	}
}

func (fr *ForwardRoutine) SendPacket(ifce *LinkInterface, DstIP net.IP, packet []byte) error {
	// Send packet out from interface ifce. packet shoud start from ip header
	fmt.Printf("Send packet out of %s to %s\n", ifce.Name(), DstIP)

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
			fmt.Printf("[Downlink INPUT] Received packet: %s -> %s\n", ip.SrcIP, ip.DstIP)

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
							fmt.Printf("[Downlink INPUT] Received DART packet: %s -> %s\n", dart.SrcFqdn, dart.DstFqdn)

							// 调用 dnsServer.resolve() 获取目标 IP
							// TODO: All packet inbound from downlink will be processed to uplink. thus, shouldn't call resolve, which is used to find downlink interface
							outIfce, destIp, _ := DNS_SERVER.Resolve(string(dart.DstFqdn))
							if outIfce == nil || destIp == nil {
								// 没有找到合适的转发接口或目标 IP，丢弃报文
								packet.SetVerdict(netfilter.NF_DROP)
								continue
							}

							// 修改 IP 报头的目标地址和源地址
							ip.DstIP = destIp
							ip.SrcIP = CONFIG.Uplink.ipNet.IP
							udp.SetNetworkLayerForChecksum(ip)

							// 重新序列化 IP + UDP + DART + 原始 Payload
							buffer := gopacket.NewSerializeBuffer()
							opts := gopacket.SerializeOptions{
								FixLengths:       true,
								ComputeChecksums: true,
							}
							err := gopacket.SerializeLayers(buffer, opts, ip, udp, dart, gopacket.Payload(dart.Payload))
							if err != nil {
								log.Printf("[Downlink INPUT] Failed to serialize packet: %v", err)
								packet.SetVerdict(netfilter.NF_DROP)
								continue
							}

							// 从上行接口发出修改后的报文
							if err := fr.SendPacket(&CONFIG.Uplink.LinkInterface, destIp, buffer.Bytes()); err != nil {
								log.Printf("[Downlink INPUT] Failed to send packet: %v", err)
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
			fmt.Printf("[Downlink FORWARD] Received packet: %s -> %s\n", ip.SrcIP, ip.DstIP)
			// check whether the destip is pseudo ip
			if !PSEUDO_POOL.IsPseudoIP(ip.DstIP) {
				break
			}

			DstFqdn, DstIP, DstUdpPort, ok := PSEUDO_POOL.Lookup(ip.DstIP)
			if !ok {
				fmt.Printf("[Downlink FORWARD] DstIP %s not found in pseudo ip pool\n", ip.DstIP)
				continue NextPacket
			}

			DstFqdn = strings.TrimSuffix(DstFqdn, ".")

			server, ok := DHCP_SERVERS[fr.ifce.Name()]
			if !ok || server == nil {
				fmt.Printf("[Downlink FORWARD] no DHCP server for interface %s\n", fr.ifce.Name())
				continue NextPacket
			}

			lease, ok := server.leasesByIp[ip.SrcIP.String()]
			if !ok {
				fmt.Printf("[Downlink FORWARD] no lease for IP %s\n", ip.SrcIP)
				continue NextPacket
			}

			SrcFqdn := lease.FQDN

			if CONFIG.Uplink.DartDomain == "." {
				// 如果父域的IPv4根域，那么对于没有注册到DNS系统的设备而言，自己放在DART头中的域名是无法解析为IP的
				// 解决的办法是将自己的公网IP嵌入DART头的源地址中
				// 我们用[]作为嵌入IP地址的标志。这两个符号不是合法的域名允许的字符，因此不会被DNS服务器接受为域名
				// 也不应当将它发送到DNS服务器进行解析
				ip := CONFIG.Uplink.PublicIP
				SrcFqdn = fmt.Sprintf("%s[%d-%d-%d-%d]", SrcFqdn, ip[0], ip[1], ip[2], ip[3])
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
				log.Printf("[Downlink FORWARD] Failed to serialize packet: %v", err)
				packet.SetVerdict(netfilter.NF_DROP)
				continue NextPacket
			}

			packetLen := len(buffer.Bytes())
			if packetLen > MTU {
				pkt_ip := &layers.IPv4{
					Version:  4,
					TTL:      64,
					Id:       0,
					Protocol: layers.IPProtocolICMPv4,
					SrcIP:    ip.DstIP,
					DstIP:    ip.SrcIP,
				}
				suggestMTU := MTU - (packetLen - MTU)
				pkt_icmp := &layers.ICMPv4{
					TypeCode: layers.ICMPv4TypeDestinationUnreachable<<8 | layers.ICMPv4CodeFragmentationNeeded,
					Id:       0,
					Seq:      uint16(suggestMTU),
				}

				pkt_payload := gopacket.Payload(ip.Contents[:28])

				// icmp.SetNetworkLayerForChecksum(ip)
				buffer := gopacket.NewSerializeBuffer()
				opts := gopacket.SerializeOptions{
					FixLengths:       true,
					ComputeChecksums: true,
				}
				err := gopacket.SerializeLayers(buffer, opts, pkt_ip, pkt_icmp, pkt_payload)
				if err != nil {
					log.Printf("[Downlink FORWARD] Failed to serialize packet: %v", err)
					packet.SetVerdict(netfilter.NF_DROP)
					continue NextPacket
				}

				if err := fr.SendPacket(&fr.ifce, pkt_ip.DstIP, buffer.Bytes()); err != nil {
					log.Printf("[Downlink FORWARD] Failed to send packet: %v", err)
				}
				log.Printf("[Downlink FORWARD] ICMP packet too long replied to sender. Suggested MTU: %d", suggestMTU)

				packet.SetVerdict(netfilter.NF_DROP)
				continue NextPacket
			}

			// hex_dump(buffer.Bytes())
			if err := fr.SendPacket(&CONFIG.Uplink.LinkInterface, ip.DstIP, buffer.Bytes()); err != nil {
				log.Printf("[Downlink FORWARD] Failed to send packet: %v", err)
				// if err msg == 'message too long', we send a ICMP package (ICMP Type 3 Code 4 ) back to src
				if strings.Contains(err.Error(), "message too long") {
					continue NextPacket
				}
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

			ip := ipLayer.(*layers.IPv4)
			fmt.Printf("[Uplink INPUT] Received packet: %s -> %s\n", ip.SrcIP, ip.DstIP)

			// check whether it is udp
			if ip.Protocol != layers.IPProtocolUDP {
				break
			}

			udpLayer := packet.Packet.Layer(layers.LayerTypeUDP)
			if udpLayer == nil {
				break
			}

			udp := udpLayer.(*layers.UDP)
			fmt.Printf("[Uplink INPUT] Received udp packet: %s -> %s\n", udp.SrcPort, udp.DstPort)
			if udp.DstPort != DARTPort {
				break
			}

			dartLayer := packet.Packet.Layer(LayerTypeDART)
			if dartLayer == nil {
				break
			}

			dart := dartLayer.(*DART)

			// Now the DstFqdn may looks like c1.sh.cn.[192-168-2.100]
			// We need to check it. If the last part is a ip address, we need to remove it.
			// 我们将DstFqdn中从第一个"["开始的部分全部删除
			DstFqdn := dns.Fqdn(trimIpSuffix(string(dart.DstFqdn)))
			fmt.Printf("[Uplink INPUT] Received dart packet: %s -> %s\n", dart.SrcFqdn, DstFqdn)

			outIfce, destIp, supportDart := DNS_SERVER.Resolve(DstFqdn)
			if outIfce == nil || destIp == nil {
				// 没找到合适的转发接口或目标IP
				packet.SetVerdict(netfilter.NF_DROP)
				continue NextPacket
			}

			buffer := gopacket.NewSerializeBuffer()
			opts := gopacket.SerializeOptions{
				FixLengths:       true,
				ComputeChecksums: true,
			}

			var err error
			if supportDart {
				// 更新 IP 地址
				ip.SrcIP = outIfce.Addr()
				ip.DstIP = destIp

				// 重新构造 UDP 层，为计算校验和准备
				udp.SetNetworkLayerForChecksum(ip)

				// 重新序列化 IP + UDP + DART + 原始 Payload

				err = gopacket.SerializeLayers(buffer, opts,
					ip, udp, dart, gopacket.Payload(dart.Payload))
			} else { // dest host doesn't support DART
				// 删除 DART 报头和UDP报头
				ip.DstIP = destIp
				srcFqdn := dns.Fqdn(trimIpSuffix(string(dart.SrcFqdn))) // 有没有最后的"."有时候会变成问题。这里规格化一下。
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
						err = gopacket.SerializeLayers(buffer, opts,
							ip, tcp, gopacket.Payload(tcp.Payload))
					}
				case layers.IPProtocolUDP:
					if udpLayer := packetData.Layer(layers.LayerTypeUDP); udpLayer != nil {
						udp := udpLayer.(*layers.UDP)
						udp.SetNetworkLayerForChecksum(ip)
						err = gopacket.SerializeLayers(buffer, opts,
							ip, udp, gopacket.Payload(udp.Payload))
					}
				case layers.IPProtocolICMPv4:
					if icmpLayer := packetData.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
						icmp := icmpLayer.(*layers.ICMPv4)
						err = gopacket.SerializeLayers(buffer, opts,
							ip, icmp, gopacket.Payload(icmp.Payload)) // 此函数会重新计算icmp的checksum
					}
				default:
					err = errors.New("[Uplink INPUT] unsupported protocol in dart payload")
				}
			} // dest host doesn't support DART. logic ends here

			if err != nil {
				log.Printf("[Uplink INPUT] Failed to serialize packet: %v", err)
				packet.SetVerdict(netfilter.NF_DROP)
				continue NextPacket
			}

			// hex_dump(buffer.Bytes())
			// 从 outIfce 指定的端口发出报文
			if err := fr.SendPacket(outIfce, destIp, buffer.Bytes()); err != nil {
				log.Printf("[Uplink INPUT] Failed to send packet: %v", err)
			}

			// 报文已经改造后从另一个端口发出了。当前报文直接 Drop
			packet.SetVerdict(netfilter.NF_DROP)
			continue NextPacket
		} // inner for loop

		// 一定要给出 verdict，不然内核一直等着
		packet.SetVerdict(netfilter.NF_ACCEPT)
	}
}

func hex_dump(data []byte) {
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

	fmt.Println("Creating queues & iptable rules to capture packets...")

	var queueNo uint16 = 0

	createAndStartQueue(queueNo, CONFIG.Uplink.LinkInterface, Input)
	if err := rm.AddRule("filter", "INPUT", []string{"-i", CONFIG.Uplink.Name, "-p", "udp", "--dport", "55847", "-j", "NFQUEUE", "--queue-num", strconv.Itoa(int(queueNo))}); err != nil {
		log.Fatalf("Failed to set iptables rule for CONFIG.Uplink input: %v", err)
	}
	queueNo++

	for _, ifce := range CONFIG.Downlinks {
		createAndStartQueue(queueNo, ifce.LinkInterface, Forward)
		if err := rm.AddRule("filter", "FORWARD", []string{"-i", ifce.Name, "-j", "NFQUEUE", "--queue-num", strconv.Itoa(int(queueNo))}); err != nil {
			log.Fatalf("Failed to set iptables rule for downlink forward: %v", err)
		}
		queueNo++

		createAndStartQueue(queueNo, ifce.LinkInterface, Input)
		if err := rm.AddRule("filter", "INPUT", []string{"-i", ifce.Name, "-p", "udp", "--dport", "55847", "-j", "NFQUEUE", "--queue-num", strconv.Itoa(int(queueNo))}); err != nil {
			log.Fatalf("Failed to set iptables rule for downlink input: %v", err)
		}
		queueNo++
	}

	select {}
}

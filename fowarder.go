package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"syscall"

	"github.com/AkihiroSuda/go-netfilter-queue"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type QueueStyle int

const (
	Input QueueStyle = iota
	Forward
	Output
)

func (s QueueStyle) String() string {
	return [...]string{"Input", "Forward", "Output"}[s]
}

type ForwardRoutine struct {
	queue *netfilter.NFQueue
	style QueueStyle
	ifce  InterfaceConfig
	sock  int
}

func (fr *ForwardRoutine) Run() {
	defer fr.queue.Close()

	if fr.ifce.Direction == "uplink" {
		fr.processUplinkInputPackets()
	} else if fr.ifce.Direction == "downlink" {
		if fr.style == Input {
			fr.processDownlinkInputPackets()
		} else if fr.style == Forward {
			fr.processDownlinkForwardPackets()
		}
	}
}

func (fr *ForwardRoutine) SendPacket(ifce *InterfaceConfig, DstIP net.IP, packet []byte) error {
	// Send packet out from interface ifce. packet shoud start from ip header
	fmt.Printf("Send packet out of %s to %s\n", ifce.Name, DstIP)

	hex_dump(packet)

	addr := syscall.SockaddrInet4{}
	copy(addr.Addr[:], DstIP.To4())

	syscall.SetsockoptString(fr.sock, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, ifce.Name)
	return syscall.Sendto(fr.sock, packet, 0, &addr)
}

func (fr *ForwardRoutine) processDownlinkForwardPackets() {
	for packet := range fr.queue.GetPackets() {
		ipLayer := packet.Packet.Layer(layers.LayerTypeIPv4)
		if ipLayer != nil {
			ip := ipLayer.(*layers.IPv4)
			fmt.Printf("Received packet: %s -> %s\n", ip.SrcIP, ip.DstIP)
		}

		// 一定要给出 verdict，不然内核一直等着
		packet.SetVerdict(netfilter.NF_ACCEPT)
	}
}

func (fr *ForwardRoutine) processDownlinkInputPackets() {
	for packet := range fr.queue.GetPackets() {
		ipLayer := packet.Packet.Layer(layers.LayerTypeIPv4)
		if ipLayer != nil {
			ip := ipLayer.(*layers.IPv4)
			fmt.Printf("Received packet: %s -> %s\n", ip.SrcIP, ip.DstIP)
		}

		// 一定要给出 verdict，不然内核一直等着
		packet.SetVerdict(netfilter.NF_ACCEPT)
	}
}

func (fr *ForwardRoutine) processUplinkInputPackets() {
	// 这里处理来自uplink的报文
	// 从这个接口进来的报文，只有DART封装的需要转发，其他的都透明通过
	// 报文的去向，必须是downlink方向
	// 目的主机有两种可能：支持DART协议，或者不支持
	// 如果支持，那么保持DART报头不变，IP报头中的源地址换成本机转发接口IP，目标地址换成本地子域中的IP
	// 如果不支持，那么删除DART报头，查找DART源地址对应的伪地址（如不存在就分配）并作为IP报头源地址，目标地址换成本地子域中的IP
NextPacket:
	for packet := range fr.queue.GetPackets() {
		for range 1 {
			// Pseudo loop. if any packet which shoud pass though, break can jump to ACCEPT directly.
			// Otherwise SetVerdictWithPacket or Drop, and then continue NextPacket
			ipLayer := packet.Packet.Layer(layers.LayerTypeIPv4)
			if ipLayer == nil {
				break // Break from the inner for-loop, let the packet go through
			}

			ip := ipLayer.(*layers.IPv4)
			fmt.Printf("Received packet: %s -> %s\n", ip.SrcIP, ip.DstIP)

			// check whether it is udp
			if ip.Protocol != layers.IPProtocolUDP {
				break
			}

			udpLayer := packet.Packet.Layer(layers.LayerTypeUDP)
			if udpLayer == nil {
				break
			}

			udp := udpLayer.(*layers.UDP)
			fmt.Printf("Received udp packet: %s -> %s\n", udp.SrcPort, udp.DstPort)
			if udp.DstPort != DARTPort {
				break
			}

			dartLayer := packet.Packet.Layer(LayerTypeDART)
			if dartLayer == nil {
				break
			}

			dart := dartLayer.(*DART)
			fmt.Printf("Received dart packet: %s -> %s\n", dart.SrcFqdn, dart.DstFqdn)

			outIfce, destIp, supportDart := dnsServer.resolve(dart.DstFqdn)
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
				ip.SrcIP = outIfce.IPAddress[:]
				ip.DstIP = destIp

				// 重新构造 UDP 层，为计算校验和准备
				udp.SetNetworkLayerForChecksum(ip)

				// 重新序列化 IP + UDP + DART + 原始 Payload

				err = gopacket.SerializeLayers(buffer, opts,
					ip, udp, dart, gopacket.Payload(dart.Payload))
			} else { // dest host doesn't support DART
				// 删除 DART 报头和UDP报头
				ip.DstIP = destIp
				ip.SrcIP = globalPseudoIpPool.FindOrAllocate(string(dart.SrcFqdn), ip.SrcIP)
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
						icmp.Checksum = 0
						err = gopacket.SerializeLayers(buffer, opts,
							ip, icmp, gopacket.Payload(icmp.Payload))
					}
				default:
					err = errors.New("unsupported protocol in dart payload")
				}
			} // dest host doesn't support DART. logic ends here

			if err != nil {
				log.Printf("Failed to serialize packet: %v", err)
				packet.SetVerdict(netfilter.NF_DROP)
				continue NextPacket
			}

			// hex_dump(buffer.Bytes())
			// 从 outIfce 指定的端口发出报文
			if err := fr.SendPacket(outIfce, destIp, buffer.Bytes()); err != nil {
				log.Printf("Failed to send packet: %v", err)
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
				fmt.Printf("|")
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

func createAndStartQueue(queueNo uint16, ifce InterfaceConfig, style QueueStyle) {
	queue, err := netfilter.NewNFQueue(queueNo, 1000, netfilter.NF_DEFAULT_PACKET_SIZE)
	if err != nil {
		log.Fatal(fmt.Errorf("error creating queue: %v", err))
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

	// layers.RegisterUDPPortLayerType(0xda27, LayerTypeDART)

	fmt.Println("Creating queues to receive packets...")
	fmt.Println("Remember to exec the following command to guide packets to the right queue:")
	fmt.Println("  iptables -F     # clear all rules")

	var queueNo uint16 = 0
	for _, ifce := range globalConfig.Interfaces {
		switch ifce.Direction {
		case "uplink":
			// 创建并启动 uplink 队列
			createAndStartQueue(queueNo, ifce, Input)
			fmt.Printf("  iptables -A INPUT -i %s -p udp --dport 55847 -j NFQUEUE --queue-num %d\n", ifce.Name, queueNo)
			queueNo++
		case "downlink":
			createAndStartQueue(queueNo, ifce, Forward)
			fmt.Printf("  iptables -A FORWARD -i %s -j NFQUEUE --queue-num %d\n", ifce.Name, queueNo)
			queueNo++

			createAndStartQueue(queueNo, ifce, Input)
			fmt.Printf("  iptables -A INPUT -i %s -p udp --dport 55847 -j NFQUEUE --queue-num %d\n", ifce.Name, queueNo)
			queueNo++
		default:
			log.Printf("Unknown direction: %s", ifce.Direction)
		}
	}
}

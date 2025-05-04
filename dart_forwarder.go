package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/net/ipv4"
)

const (
	BufferSize = 65536
	// EthPIP      = 0x0800
	IpProtoDART = 17     // DART 现在使用 UDP 协议
	DARTPort    = 0xDA27 // DART 使用的端口号
	ConfigFile  = "config.yaml"
)

type EthernetHeader struct {
	DestMAC   [6]byte
	SourceMAC [6]byte
	EthType   uint16
}

type IPHeader struct {
	VersionIHL  uint8
	TypeOfSvc   uint8
	TotalLength uint16
	ID          uint16
	FlagsFrag   uint16
	TTL         uint8
	Protocol    uint8
	Checksum    uint16
	SourceIP    [4]byte
	DestIP      [4]byte
}

type UDPHeader struct {
	SourcePort uint16
	DestPort   uint16
	Length     uint16
	Checksum   uint16
}

type DARTHeader struct {
	Version    uint8
	Protocol   uint8
	DstFqdnLen uint8
	SrcFqdnLen uint8
	DstFqdn    []byte
	SrcFqdn    []byte
}

func startForwardModule() {
	// 侦听DART数据包并转发
	conn, err := net.ListenPacket("udp4", fmt.Sprintf(":%d", DARTPort))
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	raw := ipv4.NewPacketConn(conn)
	raw.SetControlMessage(ipv4.FlagInterface, true)

	var dartPktPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, 8192)
			return &buf
		},
	}

	for {
		dartPktPtr := dartPktPool.Get().(*[]byte) // 从池中获取指针
		dartPkt := *dartPktPtr                    // 解引用指针
		pktSize, cm, _, err := raw.ReadFrom(dartPkt)
		if err != nil {
			fmt.Println("recv err:", err)
			dartPktPool.Put(dartPktPtr) // 将指针放回池中
			continue
		}

		go func(cm ipv4.ControlMessage, dartPkt []byte, pktSize int) {
			defer dartPktPool.Put(dartPktPtr) // 处理完成后将指针放回池中
			// 修改：增加日志级别控制，避免输出过多调试信息
			if os.Getenv("DEBUG") == "true" {
				fmt.Printf("Processing packet on interface %d\n", cm.IfIndex)
			}
			forwardDartPacket(cm.IfIndex, dartPkt, pktSize)
		}(*cm, dartPkt, pktSize)
	}
}

func htons(value uint16) uint16 {
	return (value<<8)&0xff00 | value>>8
}

var ipIDCounter uint16
var ipIDMutex sync.Mutex

func generateIPID() uint16 {
	ipIDMutex.Lock()
	defer ipIDMutex.Unlock()
	ipIDCounter++
	return ipIDCounter
}

func sendRawIPPacket(ifaceName string, packet []byte, dstIP net.IP) error {
	// 创建 raw socket，协议为 IPPROTO_RAW
	sock, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return fmt.Errorf("socket: %v", err)
	}
	defer syscall.Close(sock)

	// 设置 IP_HDRINCL，表示我们自己构造 IP 头
	if err := syscall.SetsockoptInt(sock, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		return fmt.Errorf("setsockopt IP_HDRINCL: %v", err)
	}

	// 绑定到目标接口
	if err := syscall.SetsockoptString(sock, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, ifaceName); err != nil {
		return fmt.Errorf("bind to device: %v", err)
	}

	// 构造 sockaddr
	dstAddr := syscall.SockaddrInet4{}
	copy(dstAddr.Addr[:], dstIP.To4())

	// 发送数据
	if err := syscall.Sendto(sock, packet, 0, &dstAddr); err != nil {
		fmt.Printf("Error sending raw packet on interface %s: %v\n", ifaceName, err)
		return fmt.Errorf("sendto: %v", err)
	}

	fmt.Printf("Raw packet sent successfully on interface %s\n", ifaceName)
	return nil
}

func sendLargePacket(ifaceName string, packet []byte, dstIP net.IP) error {
	const ipHeaderLen = 20 // 固定IPv4头部，不含选项
	const mtu = 1500
	const maxFragPayload = (mtu - ipHeaderLen) &^ 7 // 8字节对齐，除最后一个分片

	if len(packet) < ipHeaderLen {
		return fmt.Errorf("packet too short for IP header")
	}

	// 原始 IP 报头
	origHeader := make([]byte, ipHeaderLen)
	copy(origHeader, packet[:ipHeaderLen])

	// 提取并保留原始字段
	origID := binary.BigEndian.Uint16(origHeader[4:6])
	proto := origHeader[9]
	srcIP := origHeader[12:16]
	dst := origHeader[16:20]

	// 分片 payload 部分（去掉原IP头）
	payload := packet[ipHeaderLen:]

	for offset := 0; offset < len(payload); {
		fragSize := maxFragPayload
		isLast := false
		if offset+fragSize >= len(payload) {
			fragSize = len(payload) - offset
			isLast = true
		}

		// 构造 IP 分片头
		ipHeader := make([]byte, ipHeaderLen)
		copy(ipHeader, origHeader)
		totalLen := ipHeaderLen + fragSize
		binary.BigEndian.PutUint16(ipHeader[2:4], uint16(totalLen)) // Total Length
		binary.BigEndian.PutUint16(ipHeader[4:6], origID)           // ID 保持一致
		fragOffset := (offset / 8) & 0x1FFF
		flags := uint16(0)
		if !isLast {
			flags |= 0x2000 // MF标志
		}
		flags |= uint16(fragOffset)
		binary.BigEndian.PutUint16(ipHeader[6:8], flags) // Flags + Fragment offset
		ipHeader[9] = proto                              // Protocol 保持不变
		copy(ipHeader[12:16], srcIP)
		copy(ipHeader[16:20], dst)

		// 清零并重算校验和
		ipHeader[10], ipHeader[11] = 0, 0
		cs := calculateChecksum(ipHeader)
		ipHeader[10] = byte(cs >> 8)
		ipHeader[11] = byte(cs & 0xFF)

		// 提取当前分片的 payload
		fragPayload := payload[offset : offset+fragSize]

		// 拼接 IP 和 payload
		fullPacket := append(ipHeader, fragPayload...)

		// 发送
		if err := sendRawIPPacket(ifaceName, fullPacket, dstIP); err != nil {
			return fmt.Errorf("failed to send fragment at offset %d: %v", offset, err)
		}

		offset += fragSize
	}

	return nil
}

// forwardDartPacket processes and forwards a DART packet.
func forwardDartPacket(iface int, dartPkt []byte, dartPktLen int) error {
	// 解析 UDP 报头
	udpHeader := UDPHeader{
		SourcePort: binary.BigEndian.Uint16(dartPkt[0:2]),
		DestPort:   binary.BigEndian.Uint16(dartPkt[2:4]),
		Length:     binary.BigEndian.Uint16(dartPkt[4:6]),
		Checksum:   binary.BigEndian.Uint16(dartPkt[6:8]),
	}

	// 检查 UDP 端口是否为 DARTPort
	if udpHeader.DestPort != DARTPort && udpHeader.SourcePort != DARTPort {
		// 支持DART协议的主机在发出DART报文的时候会将UDP源/宿端口都设置成DARTPort。但DART报文可能经过NAT44网关，
		// 源端口会发生变化。所以我们判断的标准是，源/宿端口只要有一个是DARTPort，就认为是DART报文
		fmt.Println("Not a DART packet (wrong port)")
		return nil
	}

	// 解析 DART 报头
	dartHeader := DARTHeader{}
	dartHeader.Version = dartPkt[8]
	dartHeader.Protocol = dartPkt[9]
	dartHeader.DstFqdnLen = dartPkt[10]
	dartHeader.SrcFqdnLen = dartPkt[11]

	dstBeg := 12
	dstEnd := dstBeg + int(dartHeader.DstFqdnLen)
	srcBeg := dstEnd
	srcEnd := srcBeg + int(dartHeader.SrcFqdnLen)
	// 解析 DstFqdn 和 SrcFqdn
	dartHeader.DstFqdn = dartPkt[dstBeg:dstEnd]
	dartHeader.SrcFqdn = dartPkt[srcBeg:srcEnd]

	// 打印 DART 报头信息
	// fmt.Printf("DART info: Version=%d, Protocol=%d, %s ==> %s \n",
	// 	dartHeader.Version, dartHeader.Protocol, string(dartHeader.SrcFqdn), string(dartHeader.DstFqdn))

	// 寻找目标接口：根据 DartHeader.DstFqdn 寻找目标接口，并转发数据包。
	var targetIface *InterfaceConfig
	maxMatchLength := 0

	// 检查缓存
	if cachedIface, ok := targetIfaceCache[string(dartHeader.DstFqdn)]; ok {
		targetIface = cachedIface
	} else {
		for _, iface := range globalConfig.Interfaces {
			domain := iface.Domain
			if strings.HasSuffix(string(dartHeader.DstFqdn), domain) {
				if len(domain) > maxMatchLength {
					maxMatchLength = len(domain)
					targetIface = &iface
				}
			}
		}

		if targetIface == nil {
			// fmt.Printf("no matching interface found for DstFqdn: %s, choose the uplink interface as default", string(dartHeader.DstFqdn))
			targetIface = &globalUplinkConfig
		}

		// 缓存结果
		targetIfaceCache[string(dartHeader.DstFqdn)] = targetIface
	}

	// 并发查询DNS
	ipChan := make(chan [4]byte)
	go func() {
		ipChan <- queryDNS(string(dartHeader.DstFqdn))
	}()

	// 根据targetIface中的DNS SERVER, 查询DstFQDN的IP地址
	var ipHeader = IPHeader{}
	ipHeader.DestIP = <-ipChan
	ipHeader.SourceIP = targetIface.IPAddress
	ipHeader.Protocol = IpProtoDART
	ipHeader.TotalLength = 20 + uint16(dartPktLen) // 20 bytes for IP header, pktLen for payload(DART header + payload)
	ipHeader.TTL = 64
	ipHeader.ID = generateIPID()
	ipHeader.FlagsFrag = 0
	ipHeader.Checksum = 0
	ipHeader.TypeOfSvc = 0
	ipHeader.VersionIHL = 0x45

	// 将 IP 头部和 DART 数据包组装成完整的 IP 数据包
	fullPacket := make([]byte, 20+dartPktLen)
	copy(fullPacket[:20], []byte{
		byte(ipHeader.VersionIHL), byte(ipHeader.TypeOfSvc),
		byte(ipHeader.TotalLength >> 8), byte(ipHeader.TotalLength & 0xFF),
		byte(ipHeader.ID >> 8), byte(ipHeader.ID & 0xFF),
		byte(ipHeader.FlagsFrag >> 8), byte(ipHeader.FlagsFrag & 0xFF),
		byte(ipHeader.TTL), byte(ipHeader.Protocol),
		byte(ipHeader.Checksum >> 8), byte(ipHeader.Checksum & 0xFF),
		ipHeader.SourceIP[0], ipHeader.SourceIP[1], ipHeader.SourceIP[2], ipHeader.SourceIP[3],
		ipHeader.DestIP[0], ipHeader.DestIP[1], ipHeader.DestIP[2], ipHeader.DestIP[3],
	})
	copy(fullPacket[20:], dartPkt[:dartPktLen])

	sendLargePacket(targetIface.Name, fullPacket, net.IP(ipHeader.DestIP[:]))

	// fmt.Printf("Packet successfully sent on interface %s\n", targetIface.Name)

	return nil
}

func calculateChecksum(header []byte) uint16 {
	var sum uint32
	for i := 0; i < len(header)-1; i += 2 {
		sum += uint32(header[i])<<8 | uint32(header[i+1])
	}
	// 如果 header 长度是奇数（虽然 IP 头不会），需要特殊处理
	if len(header)%2 == 1 {
		sum += uint32(header[len(header)-1]) << 8
	}

	// 折叠到16位
	for (sum >> 16) != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	return ^uint16(sum)
}

// queryDNS resolves a domain name to an IP address using the provided DNS servers.
var dnsCache = make(map[string][4]byte)
var targetIfaceCache = make(map[string]*InterfaceConfig)

func queryDNS(domain string) [4]byte {
	if ip, ok := dnsCache[domain]; ok {
		return ip
	}

	var resolvedIP [4]byte
	resolver := net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			// 固定使用 127.0.0.1 作为 DNS 服务器
			return (&net.Dialer{}).DialContext(ctx, "udp", "127.0.0.1:53")
		},
	}

	ips, err := resolver.LookupIPAddr(context.Background(), domain)
	if err != nil || len(ips) == 0 {
		fmt.Printf("Failed to resolve domain %s: %v\n", domain, err)
		return resolvedIP
	}

	copy(resolvedIP[:], ips[0].IP.To4())
	dnsCache[domain] = resolvedIP
	return resolvedIP
}

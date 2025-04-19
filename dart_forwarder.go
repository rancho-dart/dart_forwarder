package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"

	"golang.org/x/net/ipv4"
	"gopkg.in/yaml.v2"
)

const (
	BufferSize  = 65536
	EthPIP      = 0x0800
	IpProtoDART = 254
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

type DARTHeader struct {
	Version    uint8
	Protocol   uint8
	DstFqdnLen uint8
	SrcFqdnLen uint8
	DstFqdn    []byte
	SrcFqdn    []byte
}

type ConfigInterface struct {
	Name       string   `yaml:"name"`
	Direction  string   `yaml:"direction"`
	Domain     string   `yaml:"domain"`
	Gateway    string   `yaml:"gateway,omitempty"`
	DNSServers []string `yaml:"dns_servers,omitempty"`
	Index      int      //`yaml:"index,omitempty"`
	IPAddress  [4]byte  //`yaml:"ip_address,omitempty"`
}

type Config struct {
	// 根据 config.yaml 文件中的字段定义配置结构体，
	Interfaces []ConfigInterface `yaml:"interfaces"`
}

func loadConfig() (*Config, *ConfigInterface, error) {
	configFile, err := os.ReadFile(ConfigFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read config file: %v", err)
	}

	var config Config
	var uploadLink *ConfigInterface
	if err := yaml.Unmarshal(configFile, &config); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal config: %v", err)
	}

	for _, iface := range config.Interfaces {
		if iface.Direction == "uplink" {
			uploadLink = &iface
		}

		ifObj, err := net.InterfaceByName(iface.Name)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get interface by name: %v", err)
		}
		iface.Index = ifObj.Index

		addrs, err := ifObj.Addrs()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get addresses for interface %s: %v", iface.Name, err)
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok || ipNet.IP.To4() == nil {
				continue
			}

			if iface.Gateway != "" {
				gatewayIP := net.ParseIP(iface.Gateway)
				if gatewayIP == nil {
					return nil, nil, fmt.Errorf("invalid gateway IP: %s", iface.Gateway)
				}

				if ipNet.Contains(gatewayIP) {
					copy(iface.IPAddress[:], ipNet.IP.To4())
					break
				}
			}
		}
	}

	if uploadLink == nil {
		return nil, nil, fmt.Errorf("failed to find uplink interface")
	}

	return &config, uploadLink, nil
}

var globalConfig Config
var globalUplinkConfig ConfigInterface

func main() {
	// 加载配置文件
	cfg, uplink, err := loadConfig()
	if err != nil {
		fmt.Printf("Error loading config: %v\n", err)
		os.Exit(1)
	}
	globalConfig = *cfg
	globalUplinkConfig = *uplink

	// 侦听DART数据包并转发
	conn, err := net.ListenPacket("ip4:254", "0.0.0.0")
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	raw := ipv4.NewPacketConn(conn)
	raw.SetControlMessage(ipv4.FlagInterface, true)

	dartPkt := make([]byte, 1500)

	for {
		pktSize, cm, _, err := raw.ReadFrom(dartPkt) // 读取数据包。读出来的内容是IP的Payload部分。不知道为什么函数叫 ReadFrom，应该叫ReadTo才对。
		if err != nil {
			fmt.Println("recv err:", err)
			continue
		}

		// TTL in cm is always 0, this seems to be a bug in golang net package
		// 打印调试信息：IP包
		ifi, _ := net.InterfaceByIndex(cm.IfIndex)
		fmt.Printf("Recv from interface: %s:  %s ==> %s, bytes: %d\n",
			ifi.Name, cm.Src, cm.Dst, pktSize)

		// 你可以在这里进行 forwardDartPacket()
		forwardDartPacket(cm.IfIndex, dartPkt, pktSize)
	}
}

// func main() {

// 	// 为每个接口创建并绑定 socket
// 	for _, iface := range config.Interfaces {
// 		sock, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(EthPIP)))
// 		if err != nil {
// 			fmt.Printf("Error creating socket for interface %s: %v\n", iface.Name, err)
// 			continue
// 		}
// 		defer syscall.Close(sock)

// 		// 绑定 socket 到指定接口
// 		ifaceObj, err := net.InterfaceByName(iface.Name)
// 		if err != nil {
// 			fmt.Printf("Error retrieving interface index for %s: %v\n", iface.Name, err)
// 			continue
// 		}

// 		sll := &syscall.SockaddrLinklayer{
// 			Protocol: htons(EthPIP),
// 			Ifindex:  ifaceObj.Index,
// 		}

// 		if err := syscall.Bind(sock, sll); err != nil {
// 			fmt.Printf("Error binding socket to interface %s: %v\n", iface.Name, err)
// 			continue
// 		}

// 		fmt.Printf("Listening for IP packets on interface %s...\n", iface.Name)

// 		go func(ifaceName string, sock int) {
// 			pktBuffer := make([]byte, BufferSize)
// 			for {
// 				// Receive packet
// 				pktLen, _, err := syscall.Recvfrom(sock, pktBuffer, 0)
// 				if err != nil {
// 					fmt.Printf("Error receiving packet on interface %s: %v\n", ifaceName, err)
// 					continue
// 				}

// 				if pktLen < 14 { // Minimum Ethernet frame size
// 					continue
// 				}

// 				// Parse Ethernet header
// 				ethHeader := EthernetHeader{}
// 				reader := bytes.NewReader(pktBuffer[:14])
// 				if err := binary.Read(reader, binary.BigEndian, &ethHeader); err != nil {
// 					fmt.Printf("Error parsing Ethernet header on interface %s: %v\n", ifaceName, err)
// 					continue
// 				}

// 				if ethHeader.EthType != EthPIP {
// 					fmt.Printf("Non-IP packet detected on interface %s: EthType: 0x%04x\n", ifaceName, ethHeader.EthType)
// 					continue
// 				}

// 				// Parse IP header
// 				ipHeader := IPHeader{}
// 				reader = bytes.NewReader(pktBuffer[14:34])
// 				if err := binary.Read(reader, binary.BigEndian, &ipHeader); err != nil {
// 					fmt.Printf("Error parsing IP header on interface %s: %v\n", ifaceName, err)
// 					continue
// 				}

// 				if ipHeader.Protocol != IpProtoDART { // 我们只处理 DART 协议
// 					continue
// 				}

// 				if err := forwardDartPacket(ifaceName, pktBuffer, pktLen, &ethHeader, &ipHeader); err != nil {
// 					fmt.Printf("Error forwarding DART packet on interface %s: %v\n", ifaceName, err)
// 					continue
// 				}
// 			}
// 		}(iface.Name, sock)
// 	}

// 	// 防止主线程退出
// 	select {}
// }

func htons(value uint16) uint16 {
	return (value<<8)&0xff00 | value>>8
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

	// 获取目标接口索引
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("get interface: %v", err)
	}

	// 绑定到目标接口
	ifaceNameBytes := append([]byte(ifaceName), 0)
	if err := syscall.SetsockoptString(sock, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, ifaceName); err != nil {
		return fmt.Errorf("bind to device: %v", err)
	}

	// 构造 sockaddr
	dstAddr := syscall.SockaddrInet4{}
	copy(dstAddr.Addr[:], dstIP.To4())

	// 发送数据
	if err := syscall.Sendto(sock, packet, 0, &dstAddr); err != nil {
		return fmt.Errorf("sendto: %v", err)
	}

	fmt.Printf("Raw packet sent successfully on interface %s\n", ifaceName)
	return nil
}

// forwardDartPacket processes and forwards a DART packet.
func forwardDartPacket(iface int, dartPkt []byte, dartPktLen int) error {

	// 解析 DART 报头的前 4 个字段
	dartHeader := DARTHeader{}
	dartHeader.Version = dartPkt[0]
	dartHeader.Protocol = dartPkt[1]
	dartHeader.DstFqdnLen = dartPkt[2]
	dartHeader.SrcFqdnLen = dartPkt[3]

	dstBeg := 4
	dstEnd := dstBeg + int(dartHeader.DstFqdnLen)
	srcBeg := dstEnd
	srcEnd := srcBeg + int(dartHeader.SrcFqdnLen)
	// 解析 DstFqdn 和 SrcFqdn
	dartHeader.DstFqdn = dartPkt[dstBeg:dstEnd]
	dartHeader.SrcFqdn = dartPkt[srcBeg:srcEnd]

	// 打印 DART 报头信息
	fmt.Printf("DART info: Version=%d, Protocol=%d, %s ==> %s \n",
		dartHeader.Version, dartHeader.Protocol, string(dartHeader.SrcFqdn), string(dartHeader.DstFqdn))

	// 寻找目标接口：根据 DartHeader.DstFqdn 寻找目标接口，并转发数据包。
	var targetIface *ConfigInterface
	maxMatchLength := 0

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
		fmt.Printf("no matching interface found for DstFqdn: %s, choose the uplink interface as default", string(dartHeader.DstFqdn))
		targetIface = &globalUplinkConfig
	}

	// TODO: DEBUG HERE
	// 根据targetIface中的DNS SERVER, 查询DstFQDN的IP地址
	var ipHeader = IPHeader{}
	ipHeader.DestIP = queryDNS(string(dartHeader.DstFqdn))
	ipHeader.SourceIP = targetIface.IPAddress
	ipHeader.Protocol = IpProtoDART
	ipHeader.TotalLength = 20 + uint16(dartPktLen) // 20 bytes for IP header, pktLen for payload(DART header + payload)
	ipHeader.TTL = 64
	ipHeader.ID = 0
	ipHeader.FlagsFrag = 0
	ipHeader.Checksum = 0
	ipHeader.TypeOfSvc = 0
	ipHeader.VersionIHL = 0x45
	// 计算校验和
	ipHeader.Checksum = calculateChecksum(ipHeader)
	// 打印 IP 头部信息
	fmt.Printf("IP info: SrcIP=%s, DstIP=%s, Protocol=%d, TotalLength=%d\n",
		ipHeader.SourceIP, ipHeader.DestIP, ipHeader.Protocol, ipHeader.TotalLength)
	// 打印转发信息
	fmt.Printf("Forwarding DART packet from %s to %s\n", string(dartHeader.SrcFqdn), string(dartHeader.DstFqdn))

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

	sendRawIPPacket(targetIface.Name, fullPacket, net.IP(ipHeader.DestIP[:]))

	fmt.Printf("Packet successfully sent on interface %s\n", targetIface.Name)

	return nil
}

// calculateChecksum computes the checksum for an IP header.
func calculateChecksum(header IPHeader) uint16 {
	var sum uint32
	data := []byte{
		header.VersionIHL, header.TypeOfSvc,
		byte(header.TotalLength >> 8), byte(header.TotalLength & 0xFF),
		byte(header.ID >> 8), byte(header.ID & 0xFF),
		byte(header.FlagsFrag >> 8), byte(header.FlagsFrag & 0xFF),
		header.TTL, header.Protocol,
		byte(header.Checksum >> 8), byte(header.Checksum & 0xFF),
		header.SourceIP[0], header.SourceIP[1], header.SourceIP[2], header.SourceIP[3],
		header.DestIP[0], header.DestIP[1], header.DestIP[2], header.DestIP[3],
	}

	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}

	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}

	for sum > 0xFFFF {
		sum = (sum >> 16) + (sum & 0xFFFF)
	}

	return ^uint16(sum)
}

// queryDNS resolves a domain name to an IP address using the provided DNS servers.
func queryDNS(domain string) [4]byte {
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
	return resolvedIP
}

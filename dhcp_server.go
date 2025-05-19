package main

import (
	"encoding/binary"
	"strconv"
	"strings"

	// dhcp "github.com/krolaw/dhcp4"

	"log"
	"net"
	"time"

	"github.com/krolaw/dhcp4"
	"github.com/krolaw/dhcp4/conn"
	_ "github.com/mattn/go-sqlite3" // 添加 SQLite 驱动的导入
	"github.com/miekg/dns"
)

// startDHCPServerModule 启动 DHCP Server 模块

type DHCPServer struct {
	dlIfce        DownLinkInterface
	options       dhcp4.Options
	headIP        net.IP
	tailIP        net.IP
	leaseDuration time.Duration
	leasesByIp    map[string]leaseInfo // key: IP string
	leasesByFQDN  map[string]leaseInfo
	staticLeases  map[string]leaseInfo // key: MAC, value: leaseInfo
}

type leaseInfo struct {
	IP          net.IP
	MAC         string
	Expiry      time.Time
	DARTVersion int
	FQDN        string // 新增字段：完全限定域名
}

func Uint32ToIP(ipUint uint32) net.IP {
	ipBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(ipBytes, ipUint)
	return net.IP(ipBytes)
}

func IPToUint32(ip net.IP) uint32 {
	ipBytes := ip.To4()
	if ipBytes == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ipBytes)
}

var DHCP_SERVERS map[string]*DHCPServer = make(map[string]*DHCPServer)

func startDHCPServerModule() {
	// 遍历globalConfig中的下行接口，启动DHCP服务
	for _, iface := range CONFIG.Downlinks {
		if iface.AddressPool != "" {
			server := NewDHCPServer(iface)
			pc, err := conn.NewUDP4BoundListener(iface.Name, ":67")
			if err != nil {
				log.Fatalf("Error creating UDP listener for %s: %v", iface.Name, err)
			}
			DHCP_SERVERS[iface.Name] = server

			go func(pc net.PacketConn, server *DHCPServer) {
				log.Printf("DHCP server started on %s...\n", server.dlIfce.Name)
				log.Fatal(dhcp4.Serve(pc, server))
			}(pc, server)
		}
	}

	// 防止主程序退出
	select {}
}

func NewDHCPServer(dlIfce DownLinkInterface) *DHCPServer {
	// 解析地址池
	poolParts := strings.Split(dlIfce.AddressPool, "-")
	if len(poolParts) != 2 {
		log.Fatalf("Invalid address pool format for %s: %s", dlIfce.Name, dlIfce.AddressPool)
	}
	startIP := net.ParseIP(poolParts[0]).To4()
	endIP := net.ParseIP(poolParts[1]).To4()
	if startIP == nil || endIP == nil {
		log.Fatalf("Invalid IP address in pool for %s", dlIfce.Name)
	}

	// 准备DHCP选项
	options := dhcp4.Options{
		dhcp4.OptionSubnetMask: []byte(net.ParseIP("255.255.255.0").To4()),
		dhcp4.OptionRouter:     []byte(dlIfce.ipNet.IP.To4()),
		dhcp4.OptionDomainName: []byte(dlIfce.Domain),
	}

	// 添加DNS服务器
	options[dhcp4.OptionDomainNameServer] = dlIfce.ipNet.IP

	// 初始化静态租约
	staticLeases := make(map[string]leaseInfo)
	for _, binding := range dlIfce.StaticBindings {
		var fqdn string
		if binding.FQDN != "" {
			fqdn = dns.Fqdn(binding.FQDN)
		}
		staticLeases[strings.ToLower(binding.MAC)] = leaseInfo{
			IP:          net.ParseIP(binding.IP).To4(),
			MAC:         strings.ToLower(binding.MAC),
			Expiry:      time.Now().Add(24 * time.Hour), // 静态租约默认24小时
			FQDN:        fqdn,
			DARTVersion: binding.DARTVersion,
		}
	}

	// 从数据库中加载租约信息
	var leasesByIp = make(map[string]leaseInfo)
	var leasesByFQDN = make(map[string]leaseInfo)
	if dlIfce.AddressPool != "" {
		rows, err := DB.Query("SELECT mac_address, ip_address, fqdn, dart_version, Expiry FROM dhcp_leases")
		if err != nil {
			log.Printf("Error reading from SQLite database: %v\n", err)
		}
		defer rows.Close()

		for rows.Next() {
			var mac, ip, expiryStr, fqdn string
			var dartVersion int
			err := rows.Scan(&mac, &ip, &fqdn, &dartVersion, &expiryStr)
			if err != nil {
				log.Printf("Error scanning row: %v\n", err)
				continue
			}
			expiry, err := time.Parse(time.RFC3339, expiryStr)
			if err != nil {
				log.Printf("Error parsing expiry time: %v\n", err)
				continue
			}
			leasesByIp[ip] = leaseInfo{
				IP:          net.ParseIP(ip).To4(),
				MAC:         mac,
				Expiry:      expiry,
				DARTVersion: dartVersion,
				FQDN:        fqdn,
			}
			leasesByFQDN[fqdn] = leaseInfo{
				IP:          net.ParseIP(ip).To4(),
				MAC:         mac,
				Expiry:      expiry,
				DARTVersion: dartVersion,
				FQDN:        fqdn,
			}
		}
	}

	return &DHCPServer{
		dlIfce:        dlIfce,
		options:       options,
		headIP:        startIP,
		tailIP:        endIP,
		leaseDuration: 24 * time.Hour, // 默认租约24小时
		leasesByIp:    leasesByIp,
		leasesByFQDN:  leasesByFQDN,
		staticLeases:  staticLeases,
	}
}

func HasPrefixFold(s, prefix string) bool {
	if len(s) < len(prefix) {
		return false
	}
	return strings.EqualFold(s[:len(prefix)], prefix)
}

func TrimPrefixFold(s, prefix string) string {
	if len(s) < len(prefix) {
		return s
	}
	if strings.EqualFold(s[:len(prefix)], prefix) {
		return s[len(prefix):]
	}
	return s
}

func TrimSuffixFold(s, suffix string) string {
	if len(s) < len(suffix) {
		return s
	}
	if strings.EqualFold(s[len(s)-len(suffix):], suffix) {
		return s[:len(s)-len(suffix)]
	}
	return s
}

func (s *DHCPServer) generateFQDN(ip, requestedHostname string) string {
	// 优先返回已有 lease 中的 FQDN
	if lease, ok := s.leasesByIp[ip]; ok && lease.FQDN != "" {
		return lease.FQDN
	}

	domainSuffix := "." + s.dlIfce.Domain

	// 没有请求 hostname，使用 IP 构造
	if requestedHostname == "" {
		return strings.ReplaceAll(ip, ".", "-") + domainSuffix
	}

	// 请求的是完整的 FQDN
	if strings.HasSuffix(requestedHostname, domainSuffix) {
		pureName := TrimSuffixFold(requestedHostname, domainSuffix)
		if pureName != "" {
			return strings.ReplaceAll(pureName, ".", "-") + domainSuffix
		}
	}

	// 请求的是裸主机名或其它域的 hostname
	if requestedHostname != s.dlIfce.Domain {
		return strings.ReplaceAll(TrimSuffixFold(requestedHostname, "."), ".", "-") + domainSuffix
	}

	// fallback：用 IP 构造
	return strings.ReplaceAll(ip, ".", "-") + domainSuffix
}

func (s *DHCPServer) ServeDHCP(p dhcp4.Packet, msgType dhcp4.MessageType, options dhcp4.Options) dhcp4.Packet {
	mac := strings.ToLower(p.CHAddr().String())

	switch msgType {
	case dhcp4.Discover:
		// 检查静态绑定
		if lease, ok := s.staticLeases[mac]; ok {
			return dhcp4.ReplyPacket(p, dhcp4.Offer, s.dlIfce.ipNet.IP, lease.IP, s.leaseDuration,
				s.options.SelectOrderOrAll(options[dhcp4.OptionParameterRequestList]))
		}

		// 动态分配IP
		ip := s.findFreeIP(mac)
		if ip == nil {
			return nil
		}
		return dhcp4.ReplyPacket(p, dhcp4.Offer, s.dlIfce.ipNet.IP, ip, s.leaseDuration,
			s.options.SelectOrderOrAll(options[dhcp4.OptionParameterRequestList]))
	case dhcp4.Request:
		// 检查是否是发给我们的请求
		if server, ok := options[dhcp4.OptionServerIdentifier]; ok && !net.IP(server).Equal(s.dlIfce.ipNet.IP) {
			return nil
		}

		var reqIP net.IP
		if lease, ok := s.staticLeases[mac]; ok {
			// 静态IP分配
			reqIP = lease.IP
		} else {
			// 动态IP分配
			reqIP = net.IP(options[dhcp4.OptionRequestedIPAddress])
			if reqIP == nil {
				reqIP = net.IP(p.CIAddr())
			}
		}

		if reqIP != nil && !reqIP.Equal(net.IPv4zero) {
			var dartVersion int = 0
			var fqdn string = ""
			var fqdnResolved bool = false

			lease, ok := s.staticLeases[mac]
			if ok && reqIP.Equal(lease.IP) {
				dartVersion = lease.DARTVersion
				fqdn = lease.FQDN
				fqdnResolved = fqdn != ""
			}

			if !fqdnResolved || s.isInPool(reqIP) {
				if dartVersionBin, ok := options[224]; ok {
					dartVersionStr := string(dartVersionBin)
					if HasPrefixFold(dartVersionStr, "Dart:v") {
						versionStr := TrimPrefixFold(dartVersionStr, "Dart:v")
						dartVersion, _ = strconv.Atoi(versionStr) // If error, returns 0
					}
				}

				// 获取FQDN
				hostname := ""
				if fqdnBin, ok := options[dhcp4.OptionHostName]; ok {
					hostname = dns.Fqdn(string(fqdnBin))
				}

				fqdn = s.generateFQDN(reqIP.String(), hostname) // Option hostname (if any) is used as the suggested hostname to generate FQDN
			}

			if fqdn != "" {
				// 通常DHCP客户端并不会采纳DHCP SERVER返回给它的HOSTNAME，但是我们可以将这个HOSTNAME存储在服务器上，
				// 将来需要将客户机发来的IP报文转换成DART报文的时候可以使用这个FQDN
				// 客户机如果想要知道服务器分配给它的FQDN是什么，可以通过DNS反查IP

				lease, ok := s.leasesByFQDN[fqdn] // 看看此FQDN是不是已经分配出去了（有可能不同主机配置了同一个主机名）

				if !ok || lease.MAC == mac { // 如果没分配，或者虽然已分配但MAC地址一致，则创建/更新lease信息
					s.leasesByIp[reqIP.String()] = leaseInfo{
						IP:          reqIP,
						MAC:         mac,
						Expiry:      time.Now().Add(s.leaseDuration),
						DARTVersion: dartVersion,
						FQDN:        fqdn,
					}

					s.leasesByFQDN[fqdn] = leaseInfo{
						IP:          reqIP,
						MAC:         mac,
						Expiry:      time.Now().Add(s.leaseDuration),
						DARTVersion: dartVersion,
						FQDN:        fqdn,
					}

					// write to db
					log.Printf("Write to db: mac=%s, ip=%s, dart_version=%d, fqdn=%s, Expiry=%s\n", mac, reqIP.String(), dartVersion, fqdn, time.Now().Add(s.leaseDuration).Format(time.RFC3339))
					_, err := DB.Exec("INSERT OR REPLACE INTO dhcp_leases (mac_address, ip_address, dart_version, fqdn, Expiry) VALUES (?, ?, ?, ?, ?)",
						mac, reqIP.String(), dartVersion, fqdn, time.Now().Add(s.leaseDuration).Format(time.RFC3339))
					if err != nil {
						log.Printf("Error writing to SQLite database: %v\n", err)
					}
					return dhcp4.ReplyPacket(p, dhcp4.ACK, s.dlIfce.ipNet.IP, reqIP, s.leaseDuration,
						s.options.SelectOrderOrAll(options[dhcp4.OptionParameterRequestList]))
				}
			}
		}
		return dhcp4.ReplyPacket(p, dhcp4.NAK, s.dlIfce.ipNet.IP, nil, 0, nil)

	case dhcp4.Release, dhcp4.Decline:
		// 释放租约
		for ip, li := range s.leasesByIp {
			if li.MAC == mac {
				delete(s.leasesByIp, ip)
				break
			}
		}
		for fqdn, li := range s.leasesByFQDN {
			if li.MAC == mac {
				delete(s.leasesByFQDN, fqdn)
				break
			}
		}

		log.Printf("Delete from db: mac=%s, ip=%s", mac, p.CIAddr())
		_, err := DB.Exec("DELETE FROM dhcp_leases WHERE mac_address = ?", mac)
		if err != nil {
			log.Printf("Failed to delete lease: %v", err)
		}
	}
	return nil
}

func (s *DHCPServer) findFreeIP(mac string) net.IP {
	now := time.Now()

	// 检查已分配的IP是否过期
	for ip, li := range s.leasesByIp {
		if li.Expiry.Before(now) {
			delete(s.leasesByIp, ip)
		}
	}

	// 从地址池中查找可用IP
	start := IPToUint32(s.headIP)
	end := IPToUint32(s.tailIP)

	for i := start; i <= end; i++ {
		ip := Uint32ToIP(i)
		if ip.Equal(net.IPv4zero) {
			continue
		}
		ipStr := ip.String()

		// 检查是否已被分配
		if li, ok := s.leasesByIp[ipStr]; !ok || li.Expiry.Before(now) {
			s.leasesByIp[ipStr] = leaseInfo{
				MAC:    mac,
				Expiry: time.Now().Add(s.leaseDuration),
			}
			return ip
		}
	}

	return nil
}

func (s *DHCPServer) isInPool(ip net.IP) bool {
	ipUint := IPToUint32(ip)
	head := IPToUint32(s.headIP)
	tail := IPToUint32(s.tailIP)
	return ipUint >= head && ipUint <= tail
}

func init() {
	// 创建表以存储DHCP租赁信息
	_, errCreateTbl := DB.Exec(`
			CREATE TABLE IF NOT EXISTS dhcp_leases (
				mac_address TEXT PRIMARY KEY,
				ip_address TEXT,
				fqdn TEXT,
				dart_version INTEGER,
				Expiry TEXT
			)
		`)
	if errCreateTbl != nil {
		log.Fatalf("Error creating table: %v", errCreateTbl)
	}
}

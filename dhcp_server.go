package main

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	// dhcp "github.com/krolaw/dhcp4"

	"log"
	"net"
	"time"

	"github.com/krolaw/dhcp4"
	"github.com/krolaw/dhcp4/conn"
	_ "github.com/mattn/go-sqlite3" // 添加 SQLite 驱动的导入
)

// startDHCPServerModule 启动 DHCP Server 模块

type DHCPServer struct {
	ifConfig      InterfaceConfig
	options       dhcp4.Options
	startIP       net.IP
	endIP         net.IP
	leaseDuration time.Duration
	leasesByIp    map[string]leaseInfo // key: IP string
	leasesByFQDN  map[string]leaseInfo
	staticLeases  map[string]string // key: MAC, value: IP
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

var dhcpServers map[string]*DHCPServer = make(map[string]*DHCPServer)

func startDHCPServerModule() {
	// 遍历globalConfig中的接口，启动DHCP服务

	// 为每个downlink接口启动DHCP服务器
	for _, iface := range globalConfig.Interfaces {
		if iface.Direction == "downlink" && iface.AddressPool != "" {
			server := NewDHCPServer(iface)
			pc, err := conn.NewUDP4BoundListener(iface.Name, ":67")
			if err != nil {
				log.Printf("Error creating UDP listener for %s: %v", iface.Name, err)
				continue
			}
			dhcpServers[iface.Name] = server

			go func(pc net.PacketConn, server *DHCPServer) {
				fmt.Printf("DHCP server started on %s...\n", server.ifConfig.Name)
				log.Fatal(dhcp4.Serve(pc, server))
			}(pc, server)
		}
	}

	// 防止主程序退出
	select {}
}

func NewDHCPServer(ifCfg InterfaceConfig) *DHCPServer {
	// 解析地址池
	poolParts := strings.Split(ifCfg.AddressPool, "-")
	if len(poolParts) != 2 {
		log.Fatalf("Invalid address pool format for %s: %s", ifCfg.Name, ifCfg.AddressPool)
	}
	startIP := net.ParseIP(poolParts[0]).To4()
	endIP := net.ParseIP(poolParts[1]).To4()
	if startIP == nil || endIP == nil {
		log.Fatalf("Invalid IP address in pool for %s", ifCfg.Name)
	}

	// 准备DHCP选项
	options := dhcp4.Options{
		dhcp4.OptionSubnetMask: []byte(net.ParseIP("255.255.255.0").To4()),
		dhcp4.OptionRouter:     []byte(net.ParseIP(ifCfg.Gateway).To4()),
		dhcp4.OptionDomainName: []byte(ifCfg.Domain),
	}

	// 添加DNS服务器
	var dnsServers []byte
	for _, dns := range ifCfg.DNSServers {
		dnsServers = append(dnsServers, net.ParseIP(dns).To4()...)
	}
	if len(dnsServers) > 0 {
		options[dhcp4.OptionDomainNameServer] = dnsServers
	}

	// 初始化静态租约
	staticLeases := make(map[string]string)
	for _, binding := range ifCfg.StaticBindings {
		staticLeases[strings.ToLower(binding.MAC)] = binding.IP
	}

	// 从数据库中加载租约信息
	var leasesByIp = make(map[string]leaseInfo)
	var leasesByFQDN = make(map[string]leaseInfo)
	if ifCfg.AddressPool != "" {
		rows, err := globalDB.Query("SELECT mac_address, ip_address, fqdn, dart_version, Expiry FROM dhcp_leases")
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
		ifConfig:      ifCfg,
		options:       options,
		startIP:       startIP,
		endIP:         endIP,
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

func (s *DHCPServer) ServeDHCP(p dhcp4.Packet, msgType dhcp4.MessageType, options dhcp4.Options) dhcp4.Packet {
	mac := strings.ToLower(p.CHAddr().String())

	switch msgType {
	case dhcp4.Discover:
		// 检查静态绑定
		if ip, ok := s.staticLeases[mac]; ok {
			staticIP := net.ParseIP(ip).To4()
			return dhcp4.ReplyPacket(p, dhcp4.Offer, net.ParseIP(s.ifConfig.Gateway).To4(), staticIP, s.leaseDuration,
				s.options.SelectOrderOrAll(options[dhcp4.OptionParameterRequestList]))
		}

		// 动态分配IP
		ip := s.findFreeIP(mac)
		if ip == nil {
			return nil
		}
		return dhcp4.ReplyPacket(p, dhcp4.Offer, net.ParseIP(s.ifConfig.Gateway).To4(), ip, s.leaseDuration,
			s.options.SelectOrderOrAll(options[dhcp4.OptionParameterRequestList]))
	case dhcp4.Request:
		// 检查是否是发给我们的请求
		if server, ok := options[dhcp4.OptionServerIdentifier]; ok && !net.IP(server).Equal(net.ParseIP(s.ifConfig.Gateway).To4()) {
			return nil
		}

		var reqIP net.IP
		if ip, ok := s.staticLeases[mac]; ok {
			// 静态IP分配
			reqIP = net.ParseIP(ip).To4()
		} else {
			// 动态IP分配
			reqIP = net.IP(options[dhcp4.OptionRequestedIPAddress])
			if reqIP == nil {
				reqIP = net.IP(p.CIAddr())
			}
		}

		var dartVersion int = 0
		if reqIP != nil && !reqIP.Equal(net.IPv4zero) {
			if s.isInPool(reqIP) || s.isInStaticLeases(mac, reqIP) {
				if dartVersionBin, ok := options[224]; ok {
					dartVersionStr := string(dartVersionBin)
					if HasPrefixFold(dartVersionStr, "Dart:v") {
						version := TrimPrefixFold(dartVersionStr, "Dart:v")
						versionInt, err := strconv.Atoi(version)
						if err == nil {
							dartVersion = versionInt
						}
					}
				}

				// 新增：获取FQDN
				hostname := ""
				if fqdnBin, ok := options[dhcp4.OptionHostName]; ok {
					hostname = string(fqdnBin)
				}

				domain := s.ifConfig.Domain

				fqdn := hostname + "." + domain

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
				fmt.Printf("Writing to SQLite database: mac_address=%s, ip_address=%s, dart_version=%d, fqdn=%s, Expiry=%s\n", mac, reqIP.String(), dartVersion, fqdn, time.Now().Add(s.leaseDuration).Format(time.RFC3339))
				_, err := globalDB.Exec("INSERT OR REPLACE INTO dhcp_leases (mac_address, ip_address, dart_version, fqdn, Expiry) VALUES (?, ?, ?, ?, ?)",
					mac, reqIP.String(), dartVersion, fqdn, time.Now().Add(s.leaseDuration).Format(time.RFC3339))
				if err != nil {
					log.Printf("Error writing to SQLite database: %v\n", err)
				}
				return dhcp4.ReplyPacket(p, dhcp4.ACK, net.ParseIP(s.ifConfig.Gateway).To4(), reqIP, s.leaseDuration,
					s.options.SelectOrderOrAll(options[dhcp4.OptionParameterRequestList]))
			}
		}
		return dhcp4.ReplyPacket(p, dhcp4.NAK, net.ParseIP(s.ifConfig.Gateway).To4(), nil, 0, nil)

	case dhcp4.Release, dhcp4.Decline:
		// 释放租约
		for ip, li := range s.leasesByIp {
			if li.MAC == mac {
				delete(s.leasesByIp, ip)
				break
			}
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
	start := IPToUint32(s.startIP)
	end := IPToUint32(s.endIP)

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
	start := IPToUint32(s.startIP)
	end := IPToUint32(s.endIP)
	return ipUint >= start && ipUint <= end
}

func (s *DHCPServer) isInStaticLeases(mac string, ip net.IP) bool {
	ok := s.staticLeases[mac] == ip.String()
	return ok
}

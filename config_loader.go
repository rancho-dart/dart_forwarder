package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"gopkg.in/yaml.v2"
)

type LinkDirection int

const (
	Upwards LinkDirection = iota // 0
	Downwards
)

const (
	ConfigFile = "/etc/dartd.yaml"
)

// StaticBinding 表示静态 MAC-IP 绑定
type StaticBinding struct {
	MAC         string `yaml:"mac"`
	IP          string `yaml:"ip"`
	FQDN        string `yaml:"fqdn,omitempty"`
	DARTVersion int    `yaml:"dart_version,omitempty"`
	DELEGATED   bool   `yaml:"delegated,omitempty"`
}

type LinkInterface struct {
	Owner interface{}
}

type cachedDnsItem struct {
	IP       net.IP
	Support  bool
	LiveTime time.Time
}

type UpLinkInterface struct {
	LinkInterface
	Name             string   `yaml:"name"`
	PublicIPResolver []string `yaml:"public_ip_resolver"`
	DNSServers       []string `yaml:"dns_servers"`
	_publicIP        net.IP
	ipNet            net.IPNet
	defaultGateway   net.IP // 上联口的默认网关
	inRootDomain     bool
	domainCache      map[string]cachedDnsItem
	cacheLock        sync.Mutex // 新增：用于保护 domainCache 的互斥锁
	ResolvableIP     net.IP
}

type DownLinkInterface struct {
	LinkInterface
	Name                string          `yaml:"name"`
	Domain              string          `yaml:"domain"`
	AddressPool         string          `yaml:"address_pool,omitempty"`
	StaticBindings      []StaticBinding `yaml:"static_bindings,omitempty"`
	PoolHeadIP          net.IP
	PoolTailIP          net.IP
	ipNet               net.IPNet // ipNet.Address 接口的IP同时用作DHCP SERVER/DNS SERVER/DEFAULT GATEWAY
	RegistedInUplinkDNS bool
	NAT44enabled        bool
}

type Config struct {
	Uplink    UpLinkInterface     `yaml:"uplink"`
	Downlinks []DownLinkInterface `yaml:"downlinks"`
}

var CONFIG Config

var _hasProbed bool

func (u *UpLinkInterface) PublicIP() net.IP {
	if !_hasProbed {
		u._publicIP, _ = probePublicIP(u.PublicIPResolver, u.DNSServers[0])
		_hasProbed = true
	}
	return u._publicIP
}

func (u *UpLinkInterface) lookupNS(domain string) (addrs []net.IP) {
	for _, dnsServer := range u.DNSServers {
		nameServers, err := resolveNsRecord(domain, dnsServer)
		if err != nil {
			logIf("error", "Error resolving NS record for %s: %v, try next dns server...\n", domain, err)
			continue
		} else if len(nameServers) == 0 {
			logIf("error", "No NS records found for %s, try next dns server...\n", domain)
			return nil
		} else {
			return nameServers
		}
	}
	// logIf("error", "No NS records found for [%s]", domain)
	return nil
}

func (u *UpLinkInterface) searchInCache(fqdn string) (ok bool, ip net.IP, supportDart bool) {
	u.cacheLock.Lock() // 新增：加锁
	defer u.cacheLock.Unlock()
	cachedDns, ok := u.domainCache[fqdn]
	if ok {
		if time.Now().Before(cachedDns.LiveTime) {
			return ok, cachedDns.IP, cachedDns.Support
		}
	}

	return // false, nil, false
}

func (u *UpLinkInterface) addToCache(fqdn string, ip net.IP, supportDart bool) {
	u.cacheLock.Lock() // 新增：加锁
	u.domainCache[fqdn] = cachedDnsItem{IP: ip, Support: supportDart, LiveTime: time.Now().Add(time.Hour * 24)}
	u.cacheLock.Unlock() // 新增：解锁
}

func (u *UpLinkInterface) resolveWithCache(fqdn string) (ip net.IP, supportDart bool) {
	// 在这里设置一个DNS CACHE。先从CACHE中查询，如果命中，直接返回
	ok, ip, supportDart := u.searchInCache(fqdn)
	if ok {
		return ip, supportDart
	}

	if u.inRootDomain {
		// 如果一台DART节点在根域，并且没有将自己注册到根域的DNS系统，那么为了报文能够返回，它会将自己的公网IP嵌入到DART报头的源地址中
		// 格式是这样的：c1.sh.cn.[A-B-C-D]，其中A.B.C.D是它的公网IP
		// 如果本设备的上联口直接接入IPv4的根域，那么我们先看看能否从FQDN中解析出IPv4地址
		parts := strings.Split(fqdn, ".")
		lastPart := parts[len(parts)-1]
		_ip := make(net.IP, 4)
		n, err := fmt.Sscanf(lastPart, "[%d-%d-%d-%d]", &_ip[0], &_ip[1], &_ip[2], &_ip[3])
		if err == nil && n == 4 {
			ip = _ip
			supportDart = true
		}
	}

	if ip == nil { // 如果解析失败，说明fqdn中没有嵌入IP。那就进入正常的DNS解析流程
		for _, dnsServer := range u.DNSServers {
			IPAddresses, _supportDart, err := resolveByQuery(fqdn, dnsServer, 0)
			if err != nil {
				logIf("error", "Error resolving A record for %s: %v, try next dns server...\n", fqdn, err)
				continue
			} else if len(IPAddresses) == 0 {
				// logIf("error", "No A records found for %s\n", fqdn)
				return nil, false
			} else {
				ip = IPAddresses[0]
				supportDart = _supportDart
				break
			}
		}
	}

	if ip != nil {
		u.addToCache(fqdn, ip, supportDart)
	}

	return
}

func (u *UpLinkInterface) probeLocation(domain string) string {
	domain = strings.TrimSuffix(domain, ".") // 去除末尾的点，标准化格式

	for {
		// 向上一级域回退
		if i := strings.Index(domain, "."); i >= 0 {
			domain = domain[i+1:]
		} else {
			break // 没有更多的父域了
		}

		query := "dart-gateway." + domain
		ip, suppDart := u.resolveWithCache(query)
		if ip != nil && suppDart {
			return domain
		}
	}

	return ""
}

func (li *LinkInterface) Name() string {
	switch v := li.Owner.(type) {
	case *DownLinkInterface:
		return v.Name
	case *UpLinkInterface:
		return v.Name
	}
	return ""
}

func (li *LinkInterface) Addr() net.IP {
	switch v := li.Owner.(type) {
	case *DownLinkInterface:
		return v.ipNet.IP
	case *UpLinkInterface:
		return v.ipNet.IP
	}
	return nil
}

// func (li *LinkInterface) ipNet() net.IPNet {
// 	switch v := li.Owner.(type) {
// 	case *DownLinkInterface:
// 		return v.ipNet
// 	case *UpLinkInterface:
// 		return v.ipNet
// 	}
// 	return net.IPNet{}
// }

func findDefaultGatewayOfIfce(ifName string) (net.IP, error) {
	// 只支持 Linux: 解析 /proc/net/route
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return nil, fmt.Errorf("failed to open /proc/net/route: %v", err)
	}
	defer f.Close()

	var line string
	buf := make([]byte, 4096)
	n, _ := f.Read(buf)
	content := string(buf[:n])
	lines := strings.Split(content, "\n")

	for _, line = range lines[1:] { // 跳过表头
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		if fields[0] != ifName {
			continue
		}
		if fields[1] != "00000000" { // 目的地址为 0.0.0.0
			continue
		}
		gatewayHex := fields[2]
		if len(gatewayHex) != 8 {
			continue
		}
		// 网关是小端序
		b := make([]byte, 4)
		for i := 0; i < 4; i++ {
			fmt.Sscanf(gatewayHex[2*i:2*i+2], "%02x", &b[i])
		}
		ip := net.IPv4(b[3], b[2], b[1], b[0]) // 将小端序转换为大端序
		return ip, nil
	}
	return nil, fmt.Errorf("default gateway not found for interface %s", ifName)
}

func findIpNetsOfIfce(ifName string) ([]net.IPNet, error) {
	ifObj, err := net.InterfaceByName(ifName)
	if err != nil {
		return nil, fmt.Errorf("failed to get interface by name: %v", err)
	}

	addrs, err := ifObj.Addrs()
	if err != nil {
		return nil, fmt.Errorf("failed to get addresses for interface %s: %v", ifName, err)
	}

	// 找出addrs中的IPv4地址
	var filteredIpNet []net.IPNet
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if ok {
			ipNet.IP = ipNet.IP.To4()
			if ipNet.IP != nil {
				filteredIpNet = append(filteredIpNet, *ipNet)
			}
		}
	}

	if len(filteredIpNet) == 0 {
		return nil, fmt.Errorf("no ipv4 addresses configured on interface %s", ifName)
	}

	return filteredIpNet, nil
}

// LoadCONFIG 加载配置文件并返回配置信息。
func LoadCONFIG() error {
	configFile, err := os.ReadFile(ConfigFile)
	if err != nil {
		return fmt.Errorf("failed to read config file: %v", err)
	}

	if err := yaml.Unmarshal(configFile, &CONFIG); err != nil {
		return fmt.Errorf("failed to unmarshal config: %v", err)
	}

	// Verify configurations of uplink interface
	CONFIG.Uplink.LinkInterface.Owner = &CONFIG.Uplink
	CONFIG.Uplink.domainCache = make(map[string]cachedDnsItem)

	ipNets, err := findIpNetsOfIfce(CONFIG.Uplink.Name)
	if err != nil {
		return fmt.Errorf("failed to get addresses for interface %s: %v", CONFIG.Uplink.Name, err)
	}
	CONFIG.Uplink.ipNet = ipNets[0]
	defaultGateway, err := findDefaultGatewayOfIfce(CONFIG.Uplink.Name)
	if err != nil {
		return fmt.Errorf("failed to find default gateway for interface %s: %v", CONFIG.Uplink.Name, err)
	}
	CONFIG.Uplink.defaultGateway = defaultGateway
	logIf("info", "Uplink interface: %s, ip: %s, mask: %s, default gateway: %s", CONFIG.Uplink.Name, CONFIG.Uplink.ipNet.IP, CONFIG.Uplink.ipNet.Mask, CONFIG.Uplink.defaultGateway)

	if len(CONFIG.Uplink.DNSServers) == 0 {
		return fmt.Errorf("Uplink.DNSServers cannot be empty")
	}

	// Verify configurations of Downlinks interfaces
	logIf("info", "Locating device position: am I delegated to any domain? .. ")
	for i := range CONFIG.Downlinks {
		dl := &CONFIG.Downlinks[i]
		dl.LinkInterface.Owner = dl

		// 将接口域名统一为小写
		dl.Domain = dns.Fqdn(strings.ToLower(dl.Domain))

		nameServers := CONFIG.Uplink.lookupNS(dl.Domain)

		// 我们先看一下返回的名字服务器中有没有上联口地址
		for _, ns := range nameServers {
			if ns.Equal(CONFIG.Uplink.ipNet.IP) {
				// 本地的域名已经成功在父域DNS服务器上解析
				dl.RegistedInUplinkDNS = true
				CONFIG.Uplink.ResolvableIP = ns
				logIf("info", "PASS: domain [%s] on interface [%s] has been delegated to [%s] by dns server(s) on uplink interface",
					dl.Domain, dl.Name, CONFIG.Uplink.ipNet.IP)
				break
			}
		}

		// 如果没有，那么我们再看一下名字服务器中有没有上联口的公网地址
		if !dl.RegistedInUplinkDNS && isPrivateAddr(CONFIG.Uplink.Addr()) {
			for _, ns := range nameServers {
				if ns.Equal(CONFIG.Uplink.PublicIP()) {
					// 本地的域名已经成功在父域DNS服务器上解析
					dl.RegistedInUplinkDNS = true
					CONFIG.Uplink.ResolvableIP = ns
					logIf("info", "PASS: domain [%s] configured on interface [%s] has been delegated to [%s]",
						dl.Domain, dl.Name, CONFIG.Uplink.PublicIP())
					logIf("info", "Caution: you should map udp port %s:%d => %s:%d & %s:%d => %s:%d on NAT gateway",
						CONFIG.Uplink.PublicIP(), DNSPort, &CONFIG.Uplink.ipNet, DNSPort, CONFIG.Uplink.PublicIP(), DARTPort, &CONFIG.Uplink.ipNet, DARTPort)
					break
				}
			}
		}

		DartDomain := CONFIG.Uplink.probeLocation(dl.Domain)

		if DartDomain == "" {
			logIf("info", "The uplink interface of this device is connected to root domain of Internet IPv4.")
			CONFIG.Uplink.inRootDomain = true

			if !dl.RegistedInUplinkDNS {
				publicIP := CONFIG.Uplink.PublicIP()
				if publicIP != nil {
					logIf("warn", "Warning: domain [%s] configured on interface [%s] isn't delegated by dns server(s) on uplink interface. Will use public IP [%s] as DART source address", dl.Domain, dl.Name, publicIP)
				} else {
					log.Fatalf("Domain [%s] configured on interface [%s] isn't delegated by dns server(s) on uplink interface, and the public IP of uplink interface is not available. Please check your configuration.", dl.Domain, dl.Name)
				}
			}
		} else {
			logIf("info", "The uplink interface of this device is connected to DART domain: [%s]", DartDomain)

			if !dl.RegistedInUplinkDNS {
				log.Fatalf("Sub-DART-domain not allowed in undelegated DART domain. Exit.")
			}
		}

		ipNets, err := findIpNetsOfIfce(dl.Name)
		if err != nil {
			return err
		}

		// 解析 address_pool
		if dl.AddressPool != "" {
			parts := strings.Split(dl.AddressPool, "-")
			if len(parts) != 2 {
				return fmt.Errorf("invalid address_pool format: %s", dl.AddressPool)
			}

			headIP := net.ParseIP(parts[0]).To4()
			tailIP := net.ParseIP(parts[1]).To4()
			if headIP == nil || tailIP == nil {
				return fmt.Errorf("invalid IP address in address_pool: %s", dl.AddressPool)
			}

			dl.PoolHeadIP = headIP
			dl.PoolTailIP = tailIP

			// 标记是否找到合适的接口IP
			foundValidIP := false

			for _, addr := range ipNets {
				// 判断接口IP与地址池是否在同一网段
				if addr.Contains(headIP) && addr.Contains(tailIP) {
					dl.ipNet = ipNets[0]
					foundValidIP = true
					break
				}
			}

			// 如果没有找到合适的IP，则清空地址池，标记为不启动DHCP SERVER
			if !foundValidIP {
				dl.AddressPool = ""
				dl.PoolHeadIP = nil
				dl.PoolTailIP = nil
			}
		} else { // 没有配置地址池
			if len(ipNets) > 0 {
				dl.ipNet = ipNets[0]
			}
		}

		// 解析 StaticBindings
		for _, binding := range dl.StaticBindings {
			_, err := net.ParseMAC(binding.MAC)
			if err != nil {
				return fmt.Errorf("invalid MAC address in static_bindings: %s", binding.MAC)
			}
			ipAddr := net.ParseIP(binding.IP).To4()
			if ipAddr == nil {
				return fmt.Errorf("invalid IP address in static_bindings: %s", binding.IP)
			}
		}
	}

	return nil
}

func probePublicIP(websites []string, dnsServer string) (net.IP, error) {
	// 自定义 DNS 解析器（使用 TCP IPv4）
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("udp4", dnsServer+":53")
		},
	}

	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 10 * time.Second,
		Resolver:  resolver,
	}

	transport := &http.Transport{
		DialContext:       dialer.DialContext,
		ForceAttemptHTTP2: false, // 不强制使用 HTTP/2
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}

	for _, website := range websites {
		req, err := http.NewRequest("GET", website, nil)
		if err != nil {
			logIf("error", "failed to create request:", err)
			continue
		}

		// ✅ 模拟 curl 的请求头
		req.Header.Set("User-Agent", "curl/7.85.0")
		req.Header.Set("Accept", "*/*")

		resp, err := client.Do(req)
		if err != nil {
			logIf("error", "request failed:", err)
			continue
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			logIf("error", "failed to read response:", err)
			continue
		}

		ipStr := strings.TrimSpace(string(body))
		if ip := net.ParseIP(ipStr); ip != nil {
			return ip.To4(), nil
		} else {
			logIf("error", "invalid IP string from %s: %q", website, ipStr)
		}
	}

	return nil, fmt.Errorf("no valid public IP found")
}

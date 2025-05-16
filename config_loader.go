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
	MAC string `yaml:"mac"`
	IP  string `yaml:"ip"`
}

type LinkInterface struct {
	// Direction LinkDirection
	// Name      string
	// IP        net.IP
	Owner interface{}
}

type UpLinkInterface struct {
	LinkInterface
	Name             string   `yaml:"name"`
	DartDomain       string   `yaml:"dart_domain"`
	PublicIPResolver []string `yaml:"public_ip_resolver"`
	DNSServers       []string `yaml:"dns_servers"`
	PublicIP         net.IP
	ipNet            net.IPNet
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
}

type Config struct {
	Uplink    UpLinkInterface     `yaml:"uplink"`
	Downlinks []DownLinkInterface `yaml:"downlinks"`
}

var CONFIG Config

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

// LoadConfig 加载配置文件并返回配置信息。
func LoadConfig() (*Config, error) {
	configFile, err := os.ReadFile(ConfigFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(configFile, &cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %v", err)
	}

	// Verify configurations of uplink interface
	cfg.Uplink.LinkInterface.Owner = &cfg.Uplink

	ipNets, err := findIpNetsOfIfce(cfg.Uplink.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to get addresses for interface %s: %v", cfg.Uplink.Name, err)
	}
	cfg.Uplink.ipNet = ipNets[0]

	if len(cfg.Uplink.DNSServers) == 0 {
		return nil, fmt.Errorf("Uplink.DNSServers cannot be empty")
	}

	if cfg.Uplink.DartDomain == "." {
		// If the DartDomain is root domain, we probe the public IP of the uplink, because we may behind NAT gateways
		publicIP, err := probePublicIP(cfg.Uplink.PublicIPResolver, cfg.Uplink.DNSServers[0])
		if err != nil {
			return nil, err
		}
		cfg.Uplink.PublicIP = publicIP
	}

	// Verify configurations of Downlinks interfaces
	for i := range cfg.Downlinks {
		dl := &cfg.Downlinks[i]
		dl.LinkInterface.Owner = dl

		// 将接口域名统一为小写
		dl.Domain = dns.Fqdn(strings.ToLower(dl.Domain))

		ip, supportDart := DNS_SERVER.ResolveFromParentDNSServer(dl.Domain)
		if cfg.Uplink.DartDomain == "." {
			if ip != nil {
				if !ip.Equal(cfg.Uplink.PublicIP) {
					// If resolved, the two must equal
					return nil, fmt.Errorf("the uplink's public IP is not equal to the resolved IP of %s", dl.Domain)
				}
				if !supportDart {
					return nil, fmt.Errorf("the device on %s(%s) must support DART protocol", dl.Domain, ip)
				}

				dl.RegistedInUplinkDNS = true
			} else {
				// 这是上联口接入了根域，但没有注册到DNS。将来我们发出DART报文的时候，要将公网IP嵌入源地址
				dl.RegistedInUplinkDNS = false
			}
		}

		ipNets, err := findIpNetsOfIfce(dl.Name)
		if err != nil {
			return nil, err
		}

		// 解析 address_pool
		if dl.AddressPool != "" {
			parts := strings.Split(dl.AddressPool, "-")
			if len(parts) != 2 {
				return nil, fmt.Errorf("invalid address_pool format: %s", dl.AddressPool)
			}

			headIP := net.ParseIP(parts[0]).To4()
			tailIP := net.ParseIP(parts[1]).To4()
			if headIP == nil || tailIP == nil {
				return nil, fmt.Errorf("invalid IP address in address_pool: %s", dl.AddressPool)
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
		}

		// 解析 StaticBindings
		for _, binding := range dl.StaticBindings {
			_, err := net.ParseMAC(binding.MAC)
			if err != nil {
				return nil, fmt.Errorf("invalid MAC address in static_bindings: %s", binding.MAC)
			}
			ipAddr := net.ParseIP(binding.IP).To4()
			if ipAddr == nil {
				return nil, fmt.Errorf("invalid IP address in static_bindings: %s", binding.IP)
			}
		}
	}

	return &cfg, nil
}

func probePublicIP(websites []string, dnsServer string) (net.IP, error) {
	// 自定义 DNS 解析器（使用 TCP IPv4）
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("tcp4", dnsServer+":53")
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
			log.Println("failed to create request:", err)
			continue
		}

		// ✅ 模拟 curl 的请求头
		req.Header.Set("User-Agent", "curl/7.85.0")
		req.Header.Set("Accept", "*/*")

		resp, err := client.Do(req)
		if err != nil {
			log.Println("request failed:", err)
			continue
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Println("failed to read response:", err)
			continue
		}

		ipStr := strings.TrimSpace(string(body))
		if ip := net.ParseIP(ipStr); ip != nil {
			return ip.To4(), nil
		} else {
			log.Printf("invalid IP string from %s: %q", website, ipStr)
		}
	}

	return nil, fmt.Errorf("no valid public IP found")
}

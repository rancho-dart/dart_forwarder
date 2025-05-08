package main

import (
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"

	"gopkg.in/yaml.v2"
)

// StaticBinding 表示静态 MAC-IP 绑定
type StaticBinding struct {
	MAC string `yaml:"mac"`
	IP  string `yaml:"ip"`
}

type InterfaceConfig struct {
	Name           string          `yaml:"name"`
	Direction      string          `yaml:"direction"`
	Domain         string          `yaml:"domain"`
	Gateway        string          `yaml:"gateway,omitempty"`
	DNSServers     []string        `yaml:"dns_servers,omitempty"`
	AddressPool    string          `yaml:"address_pool,omitempty"`    // 新增字段
	StaticBindings []StaticBinding `yaml:"static_bindings,omitempty"` // 修改：添加 StaticBindings 字段
	APStartIP      net.IP
	APEndIP        net.IP
	Index          int //`yaml:"index,omitempty"`
	sll            *syscall.SockaddrLinklayer
	IPAddress      [4]byte //`yaml:"ip_address,omitempty"`
}

type Config struct {
	Interfaces []InterfaceConfig `yaml:"interfaces"`
}

var globalConfig Config
var globalUplinkConfig InterfaceConfig

// loadConfig 加载配置文件并返回配置信息。
func loadConfig() (*Config, *InterfaceConfig, error) {
	configFile, err := os.ReadFile(ConfigFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read config file: %v", err)
	}

	var config Config
	var uploadLink *InterfaceConfig
	if err := yaml.Unmarshal(configFile, &config); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal config: %v", err)
	}

	for i := range config.Interfaces {
		if config.Interfaces[i].Direction == "uplink" {
			uploadLink = &config.Interfaces[i]
		}

		// 将接口域名统一为小写
		config.Interfaces[i].Domain = strings.ToLower(config.Interfaces[i].Domain)

		// check if interface[i].domain ends with '.'. If not, add it.
		if !strings.HasSuffix(config.Interfaces[i].Domain, ".") {
			config.Interfaces[i].Domain += "."
		}

		ifObj, err := net.InterfaceByName(config.Interfaces[i].Name)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get interface by name: %v", err)
		}
		config.Interfaces[i].Index = ifObj.Index

		config.Interfaces[i].sll = &syscall.SockaddrLinklayer{
			Ifindex:  ifObj.Index, // 发送接口的 index，可以通过 net.InterfaceByName 获取
			Protocol: htons(syscall.ETH_P_IP),
		}

		addrs, err := ifObj.Addrs()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get addresses for interface %s: %v", config.Interfaces[i].Name, err)
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok || ipNet.IP.To4() == nil {
				continue
			}

			if config.Interfaces[i].Gateway != "" {
				gatewayIP := net.ParseIP(config.Interfaces[i].Gateway)
				if gatewayIP == nil {
					return nil, nil, fmt.Errorf("invalid gateway IP: %s", config.Interfaces[i].Gateway)
				}

				if ipNet.Contains(gatewayIP) {
					copy(config.Interfaces[i].IPAddress[:], ipNet.IP.To4())
					break
				}
			}
		}

		// 解析 address_pool
		if config.Interfaces[i].AddressPool != "" {
			parts := strings.Split(config.Interfaces[i].AddressPool, "-")
			if len(parts) != 2 {
				return nil, nil, fmt.Errorf("invalid address_pool format: %s", config.Interfaces[i].AddressPool)
			}

			startIP := net.ParseIP(parts[0]).To4()
			endIP := net.ParseIP(parts[1]).To4()
			if startIP == nil || endIP == nil {
				return nil, nil, fmt.Errorf("invalid IP address in address_pool: %s", config.Interfaces[i].AddressPool)
			}

			config.Interfaces[i].APStartIP = startIP
			config.Interfaces[i].APEndIP = endIP
		}

		// 新增：解析 StaticBindings
		for _, binding := range config.Interfaces[i].StaticBindings {
			_, err := net.ParseMAC(binding.MAC)
			if err != nil {
				return nil, nil, fmt.Errorf("invalid MAC address in static_bindings: %s", binding.MAC)
			}
			ipAddr := net.ParseIP(binding.IP).To4()
			if ipAddr == nil {
				return nil, nil, fmt.Errorf("invalid IP address in static_bindings: %s", binding.IP)
			}
		}
	}

	if uploadLink == nil {
		return nil, nil, fmt.Errorf("failed to find uplink interface")
	}

	// 检查接口域名。downlink接口域名必须是uplink接口的子域
	for i := range config.Interfaces {
		if config.Interfaces[i].Direction == "downlink" {
			if !strings.HasSuffix(config.Interfaces[i].Domain, uploadLink.Domain) {
				return nil, nil, fmt.Errorf("downlink interface %s domain must be a subdomain of uplink interface %s domain", config.Interfaces[i].Name, uploadLink.Name)
			}
		}
	}

	return &config, uploadLink, nil
}

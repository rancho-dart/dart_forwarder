package main

import (
	"fmt"
	"net"
	"os"
	"strings"

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
	Index          int     //`yaml:"index,omitempty"`
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

		ifObj, err := net.InterfaceByName(config.Interfaces[i].Name)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get interface by name: %v", err)
		}
		config.Interfaces[i].Index = ifObj.Index

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

	return &config, uploadLink, nil
}

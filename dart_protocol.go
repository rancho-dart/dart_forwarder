package main

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	DartLayerTypeID = 0xDA27
	BufferSize      = 65536
	IpProtoDART     = 17 // DART 现在使用 UDP 协议
	DNSPort         = 53
	DHCPport        = 67
	DARTPort        = 0xDA27 // DART 使用的端口号
	ConfigFile      = "config.yaml"
)

// type ProtocolType uint8

// func (d ProtocolType) String() string {
//     names := map[ProtocolType]string{
//         1: "ICMP",
// 		2: "TCP",
// 		3: "UDP",
//     }
//     if name, ok := names[d]; ok {
//         return name
//     }
//     return fmt.Sprintf("Unknown(%d)", d)
// }

type DartProtocol struct {
	Version    uint8
	Protocol   layers.IPProtocol
	DstFqdnLen uint8
	SrcFqdnLen uint8
	DstFqdn    []byte
	SrcFqdn    []byte
	Payload    []byte
}

// 实现 gopacket.Layer 接口
func (m *DartProtocol) LayerType() gopacket.LayerType {
	return gopacket.LayerType(DartLayerTypeID) // 自定义 LayerType ID
}
func (m *DartProtocol) LayerContents() []byte { return m.Payload }
func (m *DartProtocol) LayerPayload() []byte  { return nil }

var DartProtocolType = gopacket.RegisterLayerType(
	DartLayerTypeID,
	gopacket.LayerTypeMetadata{
		Name:    "DartProtocol",
		Decoder: gopacket.DecodeFunc(decodeDartProtocol),
	},
)

func decodeDartProtocol(data []byte, p gopacket.PacketBuilder) error {
	if len(data) < 4 { // 检查最小长度
		return fmt.Errorf("dart protocol packet too short")
	}

	DstFqdnLen := data[2]
	SrcFqdnLen := data[3]

	custom := &DartProtocol{
		Version:    data[0],
		Protocol:   layers.IPProtocol(data[1]),
		DstFqdnLen: DstFqdnLen,
		SrcFqdnLen: SrcFqdnLen,
		DstFqdn:    data[4 : 4+DstFqdnLen],
		SrcFqdn:    data[4+DstFqdnLen : 4+DstFqdnLen+SrcFqdnLen],
		Payload:    data[4+DstFqdnLen+SrcFqdnLen:],
	}
	p.AddLayer(custom)
	return p.NextDecoder(gopacket.LayerTypePayload) // 继续解析上层
}

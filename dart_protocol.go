// Copyright (c) 2025 rancho.dart@qq.com
// Licensed under the MIT License. See LICENSE file for details.

package main

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	DartLayerTypeID = 1000 // 用来注册到gopacket，应用内唯一即可
	BufferSize      = 65536
	IpProtoDART     = 17 // DART 现在使用 UDP 协议
	DNSPort         = 53
	DHCPport        = 67
	DARTPort        = 0xDA27 // DART 使用的端口号
	DARTOption      = 0xDA27 // DART 协议在EDNS中的选项值
)

type DART struct {
	layers.BaseLayer
	Version    uint8
	Protocol   layers.IPProtocol
	DstFqdnLen uint8
	SrcFqdnLen uint8
	DstFqdn    []byte
	SrcFqdn    []byte
	Payload    []byte
}

// 实现 gopacket.Layer 接口
func (dart *DART) HeaderLen() uint16 {
	return 4 + uint16(dart.DstFqdnLen) + uint16(dart.SrcFqdnLen)
}

func (dart *DART) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	// 计算总长度
	totalLength := 4 + len(dart.DstFqdn) + len(dart.SrcFqdn) // + len(dart.Payload)

	// 分配缓冲区
	buf, err := b.PrependBytes(totalLength)
	if err != nil {
		return err
	}

	// 填充字段
	buf[0] = dart.Version
	buf[1] = byte(dart.Protocol)
	buf[2] = dart.DstFqdnLen
	buf[3] = dart.SrcFqdnLen

	// 填充 DstFqdn
	copy(buf[4:4+len(dart.DstFqdn)], dart.DstFqdn)

	// 填充 SrcFqdn
	copy(buf[4+len(dart.DstFqdn):4+len(dart.DstFqdn)+len(dart.SrcFqdn)], dart.SrcFqdn)

	// 填充 Payload
	// copy(buf[4+len(dart.DstFqdn)+len(dart.SrcFqdn):], dart.Payload) //只填充DART报头就好，Payload不需要填

	return nil
}

func (dart *DART) NextLayerType() gopacket.LayerType {
	return dart.Protocol.LayerType()
}

var EndpointDART = gopacket.RegisterEndpointType(1000, gopacket.EndpointTypeMetadata{Name: "DART", Formatter: func(b []byte) string {
	return string(b)
}})

// // 如果设置了此函数，那么此层可以被设置为网络层。但gopacket不接受两个网络层，也就是说此层会覆盖IP层
// func (dart *DART) NetworkFlow() gopacket.Flow {
// 	return gopacket.NewFlow(EndpointDART, dart.SrcFqdn, dart.DstFqdn)
// }

func (dart *DART) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 4 { // 检查最小长度
		df.SetTruncated()
		return fmt.Errorf("dart protocol packet too short")
	}
	dart.Version = data[0]
	dart.Protocol = layers.IPProtocol(data[1])
	dart.DstFqdnLen = data[2]
	dart.SrcFqdnLen = data[3]

	// 可能有报文因为UDP端口相同被误认为是DART报文。这里做一个简单的合法性检查
	if dart.Version != 1 {
		return fmt.Errorf("unsupported dart protocol version")
	}

	if dart.Protocol != layers.IPProtocolICMPv4 &&
		dart.Protocol != layers.IPProtocolUDP &&
		dart.Protocol != layers.IPProtocolTCP {
		return fmt.Errorf("unsupported dart protocol protocol")
	}

	if len(data) < int(dart.DstFqdnLen)+int(dart.SrcFqdnLen)+4 {
		return fmt.Errorf("illigal dart packet")
	}

	dart.DstFqdn = data[4 : 4+dart.DstFqdnLen]
	dart.SrcFqdn = data[4+dart.DstFqdnLen : 4+dart.DstFqdnLen+dart.SrcFqdnLen]
	dart.Payload = data[4+dart.DstFqdnLen+dart.SrcFqdnLen:]

	return nil
}

func (dart *DART) LayerType() gopacket.LayerType {
	return LayerTypeDART
}

var LayerTypeDART = gopacket.RegisterLayerType(
	DartLayerTypeID,
	gopacket.LayerTypeMetadata{
		Name:    "DART",
		Decoder: gopacket.DecodeFunc(decodeDART),
	},
)

func (dart *DART) CanDecode() gopacket.LayerClass {
	return LayerTypeDART
}
func decodeDART(data []byte, p gopacket.PacketBuilder) error {
	dart := &DART{}
	err := dart.DecodeFromBytes(data, p)
	p.AddLayer(dart)
	// p.SetNetworkLayer(dart)  // ChatGPT说不能将自己设置为网络层（会覆盖IP层）
	if err != nil {
		return err
	}
	return p.NextDecoder(dart.NextLayerType())
}

func init() {
	layers.RegisterUDPPortLayerType(DARTPort, LayerTypeDART)
}

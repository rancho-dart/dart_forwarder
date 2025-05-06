package main

import (
	"fmt"
	"log"
	"net"

	"github.com/AkihiroSuda/go-netfilter-queue"
	nfqueue "github.com/AkihiroSuda/go-netfilter-queue"
	"github.com/google/gopacket/layers"
)

type QueueStyle int

const (
	Input QueueStyle = iota
	Forward
	Output
)

func (s QueueStyle) String() string {
	return [...]string{"Input", "Forward", "Output"}[s]
}

type ForwardRoutine struct {
	queue *netfilter.NFQueue
	style QueueStyle
	ifce  InterfaceConfig
}

func (fr *ForwardRoutine) Run() {
	defer fr.queue.Close()

	for packet := range fr.queue.GetPackets() {
		ipLayer := packet.Packet.Layer(layers.LayerTypeIPv4)
		if ipLayer != nil {
			ip := ipLayer.(*layers.IPv4)
			fmt.Printf("Received packet: %s -> %s\n", ip.SrcIP, ip.DstIP)
		}

		// 一定要给出 verdict，不然内核一直等着
		packet.SetVerdict(netfilter.NF_ACCEPT)
	}
}

// 提取公共逻辑到 createAndStartQueue 函数
func createAndStartQueue(queueNo uint16, ifce InterfaceConfig, style QueueStyle) {
	queue, err := netfilter.NewNFQueue(queueNo, 1000, netfilter.NF_DEFAULT_PACKET_SIZE)
	if err != nil {
		log.Fatal(fmt.Errorf("error creating queue: %v", err))
	}

	// fmt.Printf("Starting queue %d for interface %s,\t", queueNo, ifce.Name)

	forwardRouting := ForwardRoutine{
		queue: queue,
		style: style,
		ifce:  ifce,
	}
	go forwardRouting.Run()
}

func startForwardModule() {
	fmt.Println("Creating queues to receive packets...")
	fmt.Println("Remember to exec the following command to guide packets to the right queue:")
	fmt.Println("  iptables -F     # clear all rules")

	var queueNo uint16 = 0
	for _, ifce := range globalConfig.Interfaces {
		switch ifce.Direction {
		case "uplink":
			// 创建并启动 uplink 队列
			createAndStartQueue(queueNo, ifce, Input)
			fmt.Printf("  iptables -I INPUT -i %s -p udp -dport 55847 -j NFQUEUE --queue-num %d\n", ifce.Name, queueNo)
			queueNo++
		case "downlink":
			createAndStartQueue(queueNo, ifce, Input)
			fmt.Printf("  iptables -I INPUT -i %s -p udp -dport 55847 -j NFQUEUE --queue-num %d\n", ifce.Name, queueNo)
			queueNo++

			createAndStartQueue(queueNo, ifce, Forward)
			fmt.Printf("  iptables -I FORWARD -i %s -j NFQUEUE --queue-num %d\n", ifce.Name, queueNo)
			queueNo++
		default:
			log.Printf("Unknown direction: %s", ifce.Direction)
		}
	}
}

// 处理函数
func handlePacket(p *nfqueue.NFPacket) {
	data := p.Packet.Data()

	if len(data) < 20 {
		log.Println("Packet too short, dropped")
		p.SetVerdict(nfqueue.NF_DROP)
		return
	}

	srcIP := net.IP(data[12:16])
	dstIP := net.IP(data[16:20])
	proto := data[9]

	log.Printf("Got packet: %s -> %s, proto=%d", srcIP, dstIP, proto)

	// 示例逻辑：丢弃源 IP 为 1.2.3.4 的包
	if srcIP.Equal(net.IPv4(1, 2, 3, 4)) {
		log.Println("Dropping packet from 1.2.3.4")
		p.SetVerdict(nfqueue.NF_DROP)
		return
	}

	// 示例逻辑：如果是 UDP 就加个假 payload 再发回内核
	if proto == 17 {
		newPayload := append(data, []byte("EXTRA")...)
		p.SetVerdictWithPacket(nfqueue.NF_ACCEPT, newPayload)
		return
	}

	// 默认放行
	p.SetVerdict(nfqueue.NF_ACCEPT)
}

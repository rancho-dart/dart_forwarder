package main

// 当一台不支持Dart协议的主机查询位于其他域的主机域名时，按照DART协议的规则，返回DART网关的IP地址。这样，下一步它发送报文时会被发送到Dart网关
// 但是因为它不支持DART协议，它发送的是普通的IP报文，DART网关就不知道应该向何处转发
// 我们在此处为每一个被查询的域名生成一个唯一的伪地址返回给查询方。这个伪地址满足如下条件：
// 1. 伪地址不会出现在真实的网络中（不会被分配给真实的网络主机或设备）
// 2. 主机或路由器处理伪地址时，会把伪地址当成真实的地址一样对待
// 3. 伪地址池要足够大

import (
	"encoding/binary"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"
)

const (
	PSEUDO_IP_POOL = "198.18.0.0/15"
)

type PseudoIpEntry struct {
	Domain     string
	PseudoIP   net.IP
	RealIP     net.IP
	udpPort    uint16 // 虽然我们在发送报文的时候会将源宿端口统一设置为0xDA27，但报文通过NAT网关后源端口号会发生变化，因此我们需要记录一下以便返回时有正确的端口
	LastUsedAt time.Time
}

type PseudoIpPool struct {
	head      uint32
	tail      uint32
	next      uint32
	ttl       time.Duration
	domainMap map[string]*PseudoIpEntry
	ipMap     map[uint32]*PseudoIpEntry
	mutex     sync.RWMutex
}

func NewPseudoIpPool(ttl time.Duration, cidr string) *PseudoIpPool {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		log.Panic("invalid CIDR format")
	}
	head := ipToUint32(ipNet.IP)
	mask := binary.BigEndian.Uint32(ipNet.Mask)
	tail := head | ^mask
	p := &PseudoIpPool{
		head:      head,
		tail:      tail,
		next:      head,
		ttl:       ttl,
		domainMap: make(map[string]*PseudoIpEntry),
		ipMap:     make(map[uint32]*PseudoIpEntry),
	}

	logIf("info", "Pseudo IP pool initialized with CIDR %s, head: %s, tail: %s", cidr, uint32ToIP(head), uint32ToIP(tail))
	logIf("info", "Pseudo IP pool will clean up expired entries every day at 3 AM")

	// 设置定时任务，每天凌晨3点执行CleanupExpired
	go func() {
		for {
			now := time.Now()
			nextRun := time.Date(now.Year(), now.Month(), now.Day(), 3, 0, 0, 0, time.Local)
			if nextRun.Before(now) {
				nextRun = nextRun.Add(24 * time.Hour)
			}
			time.Sleep(nextRun.Sub(now))
			p.CleanupExpired()
		}
	}()

	p.loadPseudoAddresses() // 自动加载数据库记录
	p.BackupOnSignal(&WG)   // 注册信号处理，退出前保存伪地址池

	return p
}

// 分配或返回已有伪地址，并刷新时间
func (p *PseudoIpPool) FindOrAllocate(domain string, realIP net.IP, udpport uint16) net.IP {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	// 若已存在，刷新时间与真实地址
	if entry, exists := p.domainMap[domain]; exists {
		entry.LastUsedAt = time.Now()
		entry.RealIP = realIP
		entry.udpPort = udpport

		// 返回已有的伪地址
		logIf("debug2", "Reusing pseudo address for %s: %s", domain, entry.PseudoIP)
		return entry.PseudoIP
	}

	// 分配新地址
	cleaned := false
	for {
		for i := uint32(0); i <= p.tail-p.head; i++ {
			ipInt := p.head + ((p.next - p.head + i) % (p.tail - p.head + 1))
			if _, used := p.ipMap[ipInt]; !used {
				pseudoIP := uint32ToIP(ipInt)
				entry := &PseudoIpEntry{
					Domain:     domain,
					PseudoIP:   pseudoIP,
					RealIP:     realIP,
					udpPort:    udpport,
					LastUsedAt: time.Now(),
				}
				p.domainMap[domain] = entry
				p.ipMap[ipInt] = entry
				p.next = ipInt + 1

				logIf("debug2", "Allocated new pseudo address for %s: %s", domain, pseudoIP)
				return pseudoIP
			}
		}

		if cleaned {
			break
		}
		p.CleanupExpired()
		cleaned = true
	}

	return nil // 地址池耗尽
}

// 反查：伪地址 → 域名和真实地址
func (p *PseudoIpPool) Lookup(ip net.IP) (domain string, realIP net.IP, udpPort uint16, ok bool) {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	ipInt := ipToUint32(ip.To4())
	if entry, found := p.ipMap[ipInt]; found {
		return entry.Domain, entry.RealIP, entry.udpPort, true
	}
	return "", nil, 0, false
}

func (p *PseudoIpPool) isPseudoIP(ip net.IP) bool {
	ipInt := ipToUint32(ip.To4())
	return p.head <= ipInt && ipInt <= p.tail
}

// 清理过期项
func (p *PseudoIpPool) CleanupExpired() {
	if p.ttl == 0 {
		return
	}
	p.mutex.Lock()
	defer p.mutex.Unlock()

	logIf("info", "Cleaning up expired pseudo addresses...")
	now := time.Now()
	for ipInt, entry := range p.ipMap {
		if now.Sub(entry.LastUsedAt) > p.ttl {
			delete(p.ipMap, ipInt)
			domain := entry.Domain
			delete(p.domainMap, domain)
		}
	}
}

// 工具函数
func ipToUint32(ip net.IP) uint32 {
	return binary.BigEndian.Uint32(ip.To4())
}

func uint32ToIP(i uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, i)
	return ip
}

func (p *PseudoIpPool) SaveAllPseudoAddresses() error {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	tx, err := DB.Begin()
	if err != nil {
		return err
	}
	// 清空表
	_, err = tx.Exec("DELETE FROM pseudo_addresses")
	if err != nil {
		tx.Rollback()
		return err
	}

	stmt, err := tx.Prepare("INSERT or REPLACE INTO pseudo_addresses (Domain, PseudoIP, RealIP, udpPort, LastUsedAt) VALUES (?, ?, ?, ?, ?)")
	if err != nil {
		tx.Rollback()
		return err
	}
	defer stmt.Close()

	for _, entry := range p.domainMap {
		_, err := stmt.Exec(entry.Domain, entry.PseudoIP.String(), entry.RealIP.String(), entry.udpPort, entry.LastUsedAt.Format(time.RFC3339))
		if err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// 加载伪地址分配记录
func (p *PseudoIpPool) loadPseudoAddresses() {
	rows, err := DB.Query("SELECT Domain, PseudoIP, RealIP, udpPort, LastUsedAt FROM pseudo_addresses")
	if err != nil {
		logIf("error", "Error loading pseudo addresses: %v\n", err)
		return
	}
	defer rows.Close()

	p.mutex.Lock()
	defer p.mutex.Unlock()

	for rows.Next() {
		var domain, pseudoIPStr, realIPStr, udpPortStr, lastUsedAt string
		if err := rows.Scan(&domain, &pseudoIPStr, &realIPStr, &udpPortStr, &lastUsedAt); err != nil {
			logIf("error", "Error scanning pseudo address row: %v\n", err)
			continue
		}

		pseudoIP := net.ParseIP(pseudoIPStr)
		if pseudoIP == nil {
			logIf("error", "Invalid pseudo IP address: %s", pseudoIPStr)
			continue
		}

		ipInt := ipToUint32(pseudoIP.To4())
		if p.head > ipInt || ipInt > p.tail {
			// logIf("info", "Pseudo IP %s not in pool", pseudoIPStr)
			continue
		}

		// 解析realIP
		realIP := net.ParseIP(realIPStr)
		if realIP == nil && realIPStr != "" {
			logIf("error", "Invalid real IP address: %s", realIPStr)
			continue
		}

		// 解析udpPort
		var port uint16 = 0
		if udpPortStr != "" {
			port64, err := strconv.ParseUint(udpPortStr, 10, 16)
			if err != nil {
				logIf("error", "Invalid udpPort value: %s", udpPortStr)
				continue
			}
			port = uint16(port64)
		}

		// 解析时间
		usedAt, err := time.Parse(time.RFC3339, lastUsedAt)
		if err != nil {
			logIf("error", "Invalid timestamp format: %s", lastUsedAt)
			usedAt = time.Now() // 默认使用当前时间
		}

		entry := &PseudoIpEntry{
			Domain:     domain,
			PseudoIP:   pseudoIP,
			RealIP:     realIP,
			udpPort:    port,
			LastUsedAt: usedAt,
		}
		p.domainMap[domain] = entry
		p.ipMap[ipInt] = entry
	}

	logIf("info", "Loaded %d pseudo addresses from database", len(p.domainMap))
}

// 注册信号处理，退出前保存伪地址池

func (p *PseudoIpPool) BackupOnSignal(wg *sync.WaitGroup) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	logIf("debug1", "Signal handler registered for saving pseudo addresses on exit")

	go func() {
		<-sigChan
		logIf("info", "Saving pseudo addresses...")
		if err := p.SaveAllPseudoAddresses(); err != nil {
			logIf("error", "Failed to save pseudo addresses: %v", err)
		} else {
			logIf("info", "Pseudo addresses saved successfully.")
		}
		wg.Done()
	}()
}

func init() {
	// 初始化数据库
	// 创建表以存储伪地址分配记录
	_, errCreatePseudoTbl := DB.Exec(`
		CREATE TABLE IF NOT EXISTS pseudo_addresses (
			Domain TEXT PRIMARY KEY,
			PseudoIP TEXT NOT NULL,
			RealIP TEXT,
			udpPort INTEGER,
			LastUsedAt TEXT
		)
	`)
	if errCreatePseudoTbl != nil {
		log.Fatal("Failed to create pseudo_addresses table:", errCreatePseudoTbl)
	}
}

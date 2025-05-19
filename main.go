package main

import (
	"log"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3" // 添加 SQLite 驱动的导入
)

const (
	BIG_VERSION   = 1
	SMALL_VERSION = 0
)

func main() {
	log.Printf("DART daemon v%d.%d starting...", BIG_VERSION, SMALL_VERSION)
	// 初始化配置
	cfg, err := LoadConfig()
	if err != nil {
		log.Fatalln("Error loading config:", err)
	}
	CONFIG = *cfg

	// 1.启动 Forward 模块
	var wg sync.WaitGroup

	// 启动 DNS Server 模块
	wg.Add(1)
	go func() {
		defer wg.Done()
		startDNSServerModule()
	}()

	// 2.启动 DHCP Server 模块
	wg.Add(1)
	go func() {
		defer wg.Done()
		startDHCPServerModule()
	}()

	time.Sleep(200 * time.Millisecond)

	// Forwarder在启动的时候会检查配置的域名是否可从上联口解析，因此需要放在最后启动
	wg.Add(1)
	go func() {
		defer wg.Done()
		startForwardModule()
	}()

	// 等待所有模块完成
	wg.Wait()
}

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3" // 添加 SQLite 驱动的导入
)

const (
	BIG_VERSION   = 1
	SMALL_VERSION = 0
)

// 控制日志条目输出的辅助函数
var loglevel *string
var logIf = func(level string, format string, v ...interface{}) {
	if *loglevel == "none" {
		return
	}

	if *loglevel == "error" && level == "error" ||
		*loglevel == "warn" && (level == "warn" || level == "error") ||
		*loglevel == "info" && (level == "warn" || level == "error" || level == "info") ||
		*loglevel == "debug1" && (level == "devug1" || level == "warn" || level == "error" || level == "info") || // 输出DNS/DHCP的报文级别的调试信息
		*loglevel == "debug2" { // 输出FORWARDER的报文级别的调试信息
		log.Printf("["+level+"] "+format, v...)
	}
}

func main() {
	// 添加命令行参数解析逻辑
	loglevel = flag.String("loglevel", "none", "Set log level (none, error, warn, info, debug1, debug2)")
	flag.Parse()

	// 新增：处理 -h 参数
	if flag.Lookup("h") != nil || flag.Lookup("help") != nil {
		fmt.Println("Usage: dart_forwarder [options]")
		fmt.Println("Options:")
		fmt.Println("  -loglevel\tSet log level (none, error, warn, info, debug1, debug2)")
		fmt.Println("  -h\t\tShow this help message")
		os.Exit(0)
	}

	logIf("info", "DART daemon v%d.%d starting...", BIG_VERSION, SMALL_VERSION)
	// 初始化配置
	err := LoadCONFIG()
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}

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

// Copyright (c) 2025 rancho.dart@qq.com
// Licensed under the MIT License. See LICENSE file for details.

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

type LogLevel int

const (
	None   LogLevel = iota // 0
	Error                  // 1
	Warn                   // 2
	Info                   // 3
	Debug1                 // 4
	Debug2                 // 5
)

var logLevelToString = map[LogLevel]string{
	None:   "none",
	Error:  "error",
	Warn:   "warn",
	Info:   "info",
	Debug1: "debug1",
	Debug2: "debug2",
}
var StringToLogLevel = map[string]LogLevel{
	"none":   None,
	"error":  Error,
	"warn":   Warn,
	"info":   Info,
	"debug1": Debug1,
	"debug2": Debug2,
}

var WG sync.WaitGroup

func main() {
	// 添加命令行参数解析逻辑
	loglevel := flag.String("loglevel", "", "Set log level (none, error, warn, info, debug1, debug2)")
	flag.Parse()

	// 新增：处理 -h 参数
	if flag.Lookup("h") != nil || flag.Lookup("help") != nil {
		fmt.Println("Usage: dart_forwarder [options]")
		fmt.Println("Options:")
		fmt.Println("  -loglevel\tSet log level (none, error, warn, info, debug1, debug2)")
		fmt.Println("  -h\t\tShow this help message")
		os.Exit(0)
	}

	logIf(Info, "DART daemon v%d.%d starting...", BIG_VERSION, SMALL_VERSION)
	// 初始化配置
	err := LoadCONFIG(loglevel)
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}

	// 1.启动 DNS Server 模块
	WG.Add(1)
	go func() {
		defer WG.Done()
		startDNSServerModule()
	}()

	// 2.启动 DHCP Server 模块
	WG.Add(1)
	go func() {
		defer WG.Done()
		startDHCPServerModule()
	}()

	time.Sleep(200 * time.Millisecond)

	// Forwarder在启动的时候会检查配置的域名是否可从上联口解析，因此需要放在最后启动
	// 3.启动 Forwarder 模块
	WG.Add(1)
	go func() {
		defer WG.Done()
		startForwardModule()
	}()
	// 等待所有模块完成
	WG.Wait()
}

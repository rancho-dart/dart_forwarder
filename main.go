package main

import (
	"database/sql"
	"fmt"
	"os"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3" // 添加 SQLite 驱动的导入
)

var db *sql.DB // 新增全局变量，用于存储数据库连接

func main() {
	// 初始化配置
	cfg, uplink, err := loadConfig()
	if err != nil {
		fmt.Printf("Error loading config: %v\n", err)
		os.Exit(1)
	}
	globalConfig = *cfg
	globalUplinkConfig = *uplink

	// 初始化数据库连接
	var errDB error
	db, errDB = sql.Open("sqlite3", "./dhcp_leases.db")
	if errDB != nil {
		fmt.Printf("Failed to open SQLite database: %v\n", errDB)
		os.Exit(1)
	}
	defer db.Close() // 程序退出时关闭数据库连接

	// 创建表以存储DHCP租赁信息
	_, errDB = db.Exec(`
		CREATE TABLE IF NOT EXISTS dhcp_leases (
			mac_address TEXT PRIMARY KEY,
			ip_address TEXT,
			fqdn TEXT,
			dart_version INTEGER,
			Expiry TEXT
		)
	`)
	if errDB != nil {
		fmt.Printf("Failed to create table: %v\n", errDB)
		os.Exit(1)
	}

	// 启动 Forward 模块
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		startForwardModule()
	}()

	time.Sleep(1 * time.Second)
	// 启动 DHCP Server 模块
	wg.Add(1)
	go func() {
		defer wg.Done()
		startDHCPServerModule()
	}()

	// time.Sleep(1 * time.Second)
	// 启动 DNS Server 模块
	wg.Add(1)
	go func() {
		defer wg.Done()
		startDNSServerModule()
	}()

	// 等待所有模块完成
	wg.Wait()
}

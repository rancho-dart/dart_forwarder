package main

import (
	"database/sql"
	"log"
	"os"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3" // 添加 SQLite 驱动的导入
)

var globalDB *sql.DB // 新增全局变量，用于存储数据库连接

func initDB() (*sql.DB, error) {
	// 初始化数据库连接
	db, errOpenDB := sql.Open("sqlite3", "./dhcp_leases.db")
	if errOpenDB != nil {
		return nil, errOpenDB
	}

	// 创建表以存储DHCP租赁信息
	_, errCreateTbl := db.Exec(`
			CREATE TABLE IF NOT EXISTS dhcp_leases (
				mac_address TEXT PRIMARY KEY,
				ip_address TEXT,
				fqdn TEXT,
				dart_version INTEGER,
				Expiry TEXT
			)
		`)
	if errCreateTbl != nil {
		return nil, errCreateTbl
	}

	return db, nil
}

func main() {
	// 初始化配置
	cfg, err := LoadConfig()
	if err != nil {
		log.Fatalln("Error loading config:", err)
	}
	CONFIG = *cfg

	var errDB error
	globalDB, errDB = initDB()
	if errDB != nil {
		log.Printf("Error initializing database: %v\n", errDB)
		os.Exit(1)
	}
	defer globalDB.Close() // 程序退出时关闭数据库连接

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

	// time.Sleep(1 * time.Second)

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

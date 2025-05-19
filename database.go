package main

import (
	"database/sql"
	"log"
	"os"

	_ "github.com/mattn/go-sqlite3" // 添加 SQLite 驱动的导入
)

const (
	DartDB = "dartd.sqlite3"
	DBdir  = "/var/lib/dart"
)

func initDB() *sql.DB {
	// 确保数据库文件所在的目录存在
	if _, err := os.Stat(DBdir); os.IsNotExist(err) {
		err := os.MkdirAll(DBdir, 0755)
		if err != nil {
			log.Fatalf("Error creating directory: %v", err)
		}
	}

	// 初始化数据库连接
	db, errOpenDB := sql.Open("sqlite3", DBdir+"/"+DartDB)
	if errOpenDB != nil {
		log.Fatalf("Error opening database: %v", errOpenDB)
	}

	return db
}

var DB *sql.DB = initDB() // 新增全局变量，用于存储数据库连接

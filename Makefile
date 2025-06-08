# 编译项目的目标
build:
	@echo "Building the project..."
	go build -o bin/dartd .

# 清理编译生成的文件
clean:
	@echo "Cleaning up..."
	rm -rf bin/

# 安装目标
install:
	@echo "Installing dartd as a system service..."
	install -Dm755 bin/dartd /usr/local/bin/dartd
	install -Dm644 scripts/dartd.service /etc/systemd/system/dartd.service
	systemctl daemon-reload
	systemctl enable dartd
	systemctl start dartd

# 卸载目标
uninstall:
	@echo "Uninstalling dartd system service..."
	systemctl stop dartd
	systemctl disable dartd
	rm -f /usr/local/bin/dartd
	rm -f /etc/systemd/system/dartd.service
	systemctl daemon-reload

# 默认目标
.PHONY: build clean install uninstall
default: build
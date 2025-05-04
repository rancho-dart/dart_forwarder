# 编译项目的目标
build:
	@echo "Building the project..."
	go build -o bin/dartd .

# 清理编译生成的文件
clean:
	@echo "Cleaning up..."
	rm -rf bin/

# 默认目标
.PHONY: build clean
default: build
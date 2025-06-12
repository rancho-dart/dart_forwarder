# Build target for the project
build:
	@echo "Building the project..."
	go build -o bin/dartd .

# Clean up compiled files
clean:
	@echo "Cleaning up..."
	rm -rf bin/

# Install target
install:
	@echo "Installing dartd as a system service..."
	install -Dm755 bin/dartd /usr/local/bin/dartd
	install -Dm644 scripts/dartd.service /etc/systemd/system/dartd.service
	install -Dm644 config.yaml /etc/dartd.yaml
	systemctl stop systemd-resolve
	systemctl disable systemd-resolve
	systemctl daemon-reload
	systemctl enable dartd
	systemctl start dartd

# Uninstall target
uninstall:
	@echo "Uninstalling dartd system service..."
	systemctl stop dartd
	systemctl disable dartd
	rm -f /usr/local/bin/dartd
	rm -f /etc/systemd/system/dartd.service
	rm -f /etc/dartd.yaml
	systemctl daemon-reload
	systemctl enable systemd-resolve
	systemctl start systemd-resolve

# Default target
.PHONY: build clean install uninstall
default: build
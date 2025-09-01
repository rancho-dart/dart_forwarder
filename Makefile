# Build target for the project
build:
	@echo "Building the project..."
	go build -o bin/dartd .

# Clean up compiled files
clean:
	@echo "Cleaning up..."
	rm -rf bin/
	@echo "Build directory cleaned."

# Install target
install:
	@echo "Installing dartd as a system service..."
	@if [ -f /etc/systemd/system/dartd.service ]; then \
		echo "dartd is already installed. Performing upgrade instead..."; \
		$(MAKE) upgrade; \
	else \
		install -Dm755 bin/dartd /usr/local/bin/dartd; \
		install -Dm644 scripts/dartd.service /etc/systemd/system/dartd.service; \
		install -Dm644 config.yaml /etc/dartd.yaml; \
		systemctl stop systemd-resolved; \
		systemctl disable systemd-resolved; \
		systemctl daemon-reload; \
		systemctl enable dartd; \
		systemctl start dartd; \
		echo "dartd service has been installed, now you need to edit the config file /etc/dartd.yaml to let it start successfully."; \
	fi

# Uninstall target
uninstall:
	@echo "Uninstalling dartd system service..."
	systemctl stop dartd
	systemctl disable dartd
	rm -f /usr/local/bin/dartd
	rm -f /etc/systemd/system/dartd.service
	rm -f /etc/dartd.yaml
	systemctl daemon-reload
	systemctl enable systemd-resolved
	systemctl start systemd-resolved
	@echo "dartd service has been uninstalled."
	
# Upgrade target
upgrade:
	@echo "Upgrading dartd system service..."
	systemctl stop dartd
	install -Dm755 bin/dartd /usr/local/bin/dartd
	systemctl start dartd
	@echo "Upgrade complete."
	
# Default target
.PHONY: build clean install uninstall
default: build
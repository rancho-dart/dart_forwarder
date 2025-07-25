# Dart Forwarder

Dart Forwarder is a DART protocol forwarding program that includes the following components:

- DHCP Server: A DHCP protocol server for processing DHCP protocol data and recording whether clients support the DART protocol.
- DNS Server: A DNS protocol server for responding to DNS queries. The response message format is consistent with traditional DNS messages, but the response rules are slightly different.
- Dart Forwarder: A DART protocol forwarding router.
- NAT-DART-4: Performs forwarding from the DART protocol to IPv4.
- NAT44: Performs classic NAT forwarding.

## Features

- Forward DART protocol messages
- Implement conversion and forwarding of DART messages to IPv4 messages
- Implement NAT forwarding of IPv4 messages

## Installation

Currently, the program is only tested on Ubuntu 24.04.

1. Clone the repository:
   ```bash
   git clone https://github.com/rancho-dart/dart_forwarder.git
   cd dart_forwarder
   ```

2. Install dependencies:
   ```bash
   export GOPROXY=https://goproxy.cn,direct  # Change to your preferred proxy.
   go mod tidy
   sudo apt update
   sudo apt install libnetfilter-queue-dev
   ```
   
3. Compile the program:
   ```bash
   make
   ```
   The program will be compiled as 'bin/dartd'.


4. Install the program:
   ```bash
   sudo make install
   ```
   During installation, the program will be installed as system service 'dartd', and the configuration file will be installed as /etc/dartd.yaml.
   The service is set to start automatically after installation, but maybe can not start automatically at the first time, because the default configuration file is not suitable for your environment.

5. Configure the system:
   - dartd uses nfqueue to capture packets, it depends on the following settings:
      1) Enable IP forwarding
         Edit /etc/sysctl.conf to enable IP forwarding:
         ```bash
         net.ipv4.ip_forward=1
         ```
      2) The system has a default route. Otherwise some packets will be dropped instead of being forwarded.

   - If system is configured as Router-on-stick, you should edit /etc/ufw/sysctl.conf to disable ICMP redirect:
      ```bash
      net.ipv4.conf.all.accept_redirects=0
      net.ipv4.conf.all.send_redirects=0
      net.ipv4.conf.eth0.send_redirects = 0       # Change 'eth0' to your network interface name.
      ```
   - Make it to take effect:
      ```bash
      sudo sysctl -p
      ```

6. Configure the program:
   Edit /etc/dartd.yaml, complete the configuration.
   Then run the program to check whether the configuration is correct or not:
   ```bash
   bin/dartd 
   ```
   The program will run in the foreground and print logs to the console.
   You can use -h to see the help message, -loglevel to set the log level(-loglevel=debug2 to print the most detailed info), Ctrl+C to stop the program.
   
      Any time the service can not start sucessfully, you can run it by hand:
      ```bash
      bin/dartd -loglevel=debug2
      ```
      to find the accuracy error message.

   If the program runs successfully (e.g. it doesn't exit with a fatal message), you can press Ctrl+C to break the program and run the program as a system service.

7. Start the program as service:
   ```bash
   sudo systemctl start dartd
   ```
   Or simply reboot the system. The service will start automatically after reboot.
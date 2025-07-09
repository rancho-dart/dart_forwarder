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
   pub get
   sudo apt update
   sudo apt install libnetfilter-queue-dev
   ```
   
3. Compile the program:
   ```bash
   make
   ```

4. Configuration file:
   Copy dart.yaml to /etc/dartd.yaml.
   Edit /etc/dartd.yaml, complete the configuration.

5. Run the program:
   - As a regular program:
     ```bash
     bin/dartd 
     ```
     You can use -h to see the help message, -loglevel to set the log level, Ctrl+C to stop the program.
     The program will run in the foreground and print logs to the console.

   - As a system service:
     ```bash
     sudo make install
     ```
     After installation, the service 'dartd' will start automatically.
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

1. Clone the repository:
   ```bash
   git clone https://github.com/your-repo/dart_forwarder.git
   cd dart_forwarder
   ```

2. Install dependencies:
   ```bash
   export GOPROXY=https://goproxy.cn,direct  # If you are in China, this is suggested.
   pub get
   sudo apt update
   sudo apt install libnetfilter-queue-dev
   ```
   
3. Compile the program:
   ```bash
   make
   ```

4. Configuration file:
   Edit /etc/dartd.yaml, complete the configuration.

5. Run the program:
   - As a regular program:
     ```bash
     bin/dartd 
     ```

   - As a system service:
     ```bash
     sudo make install
     ```

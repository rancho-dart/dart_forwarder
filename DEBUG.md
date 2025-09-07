# Debug Dart Forwarder

To debug Dart Forwarder, you should have finished the installation and configuration steps, and the program 'dartd' can start successfully. (If it doesn't, please refer to the README.markdown and CONFIGURATION.md for help.)
1. Run the program:

    There are two ways to run the program:
    - Run the program as a system service:
        ```bash
        sudo systemctl start dartd
        ```
        You can specify log_level in the configration. The program will run in the background and print logs to /var/log/dartd.log.

        You can use command:
        ```bash
        tail -f /var/log/dartd.log
        ```
        to view the logs in real time.
    - Run the program by hand:
        ```bash
        sudo bin/dartd -loglevel debug2
        ```
        The program will run in the foreground and print logs to the console. You can use 
        Ctrl+C
        to stop the program.

1. Delegate a domain to this gateway

    You should get a public IP address, and a domain from your ISP. Then you configure the DART gateway:
    - Configure the public IP address to the uplink interface in the OS. Or, you can configure the public IP address to the NAT gateway, and map the DNS port and udp port 55847 to the uplink interface's private IP address.
    - Configure the uplink interface's 'dns_servers' parameter to the public DNS server of your ISP.
    - Configure the domain to the **downlink** interface's 'domain' parameter.
    - Delegate the domain to the uplink interface's DNS server.
    
    After that, you can access the domain from the public network. Let's illustrate this with dart-proto.cn. 
    
    Parse the domain from the parent domain(e.g. Internet):
    ```bash
    dig dart-proto.cn ns

    ; <<>> DiG 9.17.12 <<>> dart-proto.cn ns
    ;; global options: +cmd
    ;; Got answer:
    ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 63624
    ;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 2

    ;; OPT PSEUDOSECTION:
    ; EDNS: version: 0, flags:; udp: 1232
    ;; QUESTION SECTION:
    ;dart-proto.cn.                 IN      NS

    ;; ANSWER SECTION:
    dart-proto.cn.          600     IN      NS      ns.dart-proto.cn.

    ;; ADDITIONAL SECTION:
    ns.dart-proto.cn.       86400   IN      A       124.71.175.125

    ;; Query time: 18 msec
    ;; SERVER: 192.168.1.1#53(192.168.1.1) (UDP)
    ;; WHEN: Sun Sep 07 12:51:11 ;; MSG SIZE  rcvd: 75
    ```
    124.71.175.125 is my public IP address, and dart-proto.cn is the domain that I get from my ISP. You can see that the NS record is ns.dart-proto.cn, and the A record of ns.dart-proto.cn is 124.71.175.125. It means that the domain dart-proto.cn has been delegated to 124.71.175.125 successfully.

    Now you can try parse fqdns belonging to this domain:
    ```bash
    dig www.dart-proto.cn  @8.8.8.8

    ; <<>> DiG 9.17.12 <<>> www.dart-proto.cn @8.8.8.8
    ;; global options: +cmd
    ;; Got answer:
    ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 53243
    ;; flags: qr rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1

    ;; OPT PSEUDOSECTION:
    ; EDNS: version: 0, flags:; udp: 512
    ;; QUESTION SECTION:
    ;www.dart-proto.cn.             IN      A

    ;; ANSWER SECTION:
    www.dart-proto.cn.          60  IN      CNAME   dart-gateway.dart-proto.cn.
    dart-gateway.dart-proto.cn. 60  IN      A       124.71.175.125

    ;; Query time: 275 msec
    ;; SERVER: 8.8.8.8#53(8.8.8.8) (UDP)
    ;; WHEN: Sun Sep 07 12:57:51 ;; MSG SIZE  rcvd: 89
    ```
    You can see that no matter what fqdn you query (even if doesn't exist), only if the fqdn belongs to the domain, the result is always a CNAME record pointing to dart-gateway.dart-proto.cn, and the A record of dart-gateway.dart-proto.cn pointing to 124.71.175.125.

    To those clients who do not support DART, they get the IP address of the DART gateway, and if it sends out a http request to this address consequently, we can provide a web page to lead the client to upgrade to support DART; To those clients who support DART, they not only get the IP address, but also the DART-ready status of the DART gateway.

    This step is optional. If you don't do this, hosts in the subdomain will not be accessible from the parent domain.

1. Prepare the clients

    DART is a very powerful protocol. A IPv4-only device can be supported very well by NAT-DART-4 (which means, the device knows nothing about DART). In fact, the client really needs nothing special to do to support DART. But to ensure the DART gateway to recognize the client correctly, you need to ensure that the client meets the following conditions:
    - If the client gets its IP address via DHCP, you need to make sure that it gets the its IP address from the embeded DHCP server of the DART gateway.
    - If the client gets its IP address via static configuration, you need to make sure that its mac/ip/fqdn have been configured in the static_bindings parameter of the DART gateway's configuration file.
    - Make sure that there are no duplicate hostnames in each subdomain.

    Now you can try to access the client inside the subdomain from the parent domain with a DART-ready client, such as a Windows 10/11 PC with DartWinDivert installed, or a PC (Windows 10/11 or Linux) behind another DART gateway.

    You can use tcpdump or WireShark to capture the packets between the DART gateway and the client. There is a DART protocol plugin 'dart.lua' in the wireshark folder of this repo, simply copy it to the wireshark plugins folder and restart wireshark. Then WireShark will show DART packets.

Enjoy DART!
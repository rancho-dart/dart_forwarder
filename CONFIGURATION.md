# Configuration of Dart Forwarder
Dart Forwarder is the core service program of the DART Gateway. In addition to the forwarding function, it also has a built-in DHCP server and a DNS server.

Dart Forwarder is configured through a YAML file. The configuration file is located at /etc/dartd.yaml.
## Typical configuration
```yaml
log_level: info
uplink:
  name: eth0
  pmtu: 1492
  public_ip_resolver:
    - http://ifconfig.me
    - http://ip.sb
    - http://ident.me  
    - http://ip.dnsexit.com
    - http://ip.tyk.nu
  dns_servers:
    - 10.11.0.100

downlinks:
  - name: eth1
    address_pool: 10.11.1.100-10.11.1.199
    domain: bj.cn
    gateway: 10.11.1.1
    static_bindings:
      - mac: "00:0c:29:f1:65:17"
        ip: "10.11.1.99"
        fqdn: "dart.bj.cn"
        dart_version: 0
        delegated: true
```
## Configuration Parameters
- log_level:

    The log level of the program. The log level can be one of the following:
    - none
    - error
    - warn
    - info (default)
    - debug1
    - debug2
    
    You can override the log level by specifying the log level in the command line:
    ```bash
    sudo bin/dartd -loglevel debug2
    ```
    When running as a system service, the log level is determined by the log_level parameter in the configuration file. And the output will be redirected to /var/log/dartd.log.

- uplink: 

    Required. The uplink interface.

    The DART protocol uses DNS as its control plane and inherits DNS’s hierarchical tree structure in its architecture. Each DART gateway connects to its parent domain via an uplink and derives one or more subdomains through downlink connections.

    In this prototype system, only one uplink interface is allowed to be configured.

  - name: 
  
    Required. The name of the uplink interface.
  - pmtu: 
  
    The maximum transmission unit of the uplink interface.
  
    Note: The PMTU is not the interface MTU; it is the maximum MTU along the entire path from the interface to the public network gateway. On Ubuntu, you can use:
    ```sh
     tracepath 8.8.8.8 
    ```
     to detect this value, and take the smallest PMTU observed at the first public address as the result.

     If you ommit this line, the default will be set to 1500. But PMTU is a very important parameter, incorrect PMTU may cause the DART protocol to fail. **Be sure to use the above command to determine a valid PMTU value.**
  - public_ip_resolver: 
  
    The resolver used to get the public IP of the uplink interface. Sometimes we need the public IP to configure the DNS server when it is behind a NAT.

    The resolver is a list of URLs. When you :
    ```
    curl <url>
    ```
    and the returned value is your public IP address, the url is a valid resolver.

  - dns_servers: 
    
    Required. 
    
    The DNS servers used to resolve domain names in parent domain.

- downlinks: 

    Required. The downlink interfaces. 
    
    In this prototype system, only one downlink interface is suggested to be configured.

    - name: 
    
        Required. The name of the downlink interface. If is same as the uplink interface, the system will work in router-on-a-stick mode. In this case, please delete the address_pool line to disable the embedded DHCP server.
    - address_pool: 
    
        The address pool used to assign IP addresses to clients. The embeded DHCP server will use this pool to assign IP addresses to clients. Make sure the pool is at the same subnet as the downlink interface.
    - domain: 

        The domain name of the downlink interface. If you want hosts in this subdomain to be able to be accessible from the parent domain, you need to delegate this domain to the uplink interface's dns server(e.g. this host is the NS server of this domain).

    - gateway: 
    
        Required. The gateway of the downlink interface. Currently, it is also used as the DHCP server, and the DNS server.

    - static_bindings: 

        First, these configurations allow the DHCP server to assign specific IP addresses to devices with designated MAC addresses.
        
        Second, for terminals that do not obtain their IP via DHCP, these configurations enable the forwarding program to recognize their IP addresses (completing the mapping from hostname to IP).
        
        Finally, static configurations can be used to specify the derived subdomains.
        - mac: 
        
            The MAC address of the client.
        - ip: 

            The IP address of the client.
        - fqdn: 
        
            The FQDN of the client.
        - dart_version:

            The DART version of the client. Can be 0 or 1. 0 means does not support DART. 1 means supports DART version 1. Currently, DART has only version 1. If ommitted, the default value is 0. 
            
            If the client supports DART, this DART gateway will forward DART encapsulated packets to the client directly. 
            
            If not, the DART gateway will perform NAT-DART-4 to forward packets to the client, and vice versa.

        - delegated: 
        
            Whether the client is delegated. If set to true, this client is treated as a dart gateway to its subdomain.

After configuring the program, you can run it by hand:
```bash
sudo bin/dartd -loglevel debug2
```
to check whether the configuration is correct or not. 

If it runs successfully (e.g. it doesn't exit with a fatal message), you can press Ctrl+C to break the program and run the program as a system service:
```bash
sudo systemctl start dartd
```

Now you can turn to DEBUG.md to see how to debug the program.

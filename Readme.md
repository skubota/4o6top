IPv4 over IPv6 network top(4o6top)
===================

DESCRIPTION

4o6top is a simple tool to track the session information of IPv4 packets on IPv6


usage

	$ tcpdump -l -w - 'ip6' | 4o6top

option
```
  -h int
    	height (default 30)
  -i int
    	reflesh interval (default 1)
  -r string
    	Read pcap file (default "-")
  -t int
    	entry view ttl (default 3)
```

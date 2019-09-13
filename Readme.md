# 4o6top

IPv4 over IPv6 network top(4o6top)

## DESCRIPTION

4o6top is a simple tool to track the session information of IPv4 packets on IPv6

### screen shot
![sc](https://github.com/skubota/4o6top/raw/master/media/4o6top.gif)

### requrement

 libpcap (libpcap-devel)

### usage

	$ go get github.com/skubota/4o6top
	$ tcpdump -i eth0 -l -w - 'ip6' | 4o6top -s xxx.xxx.xxx.xxx -h 30 -t 10 -i 1

### option

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

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details

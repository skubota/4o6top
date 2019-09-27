# 4o6top

IPv4 over IPv6 network top(4o6top)

## DESCRIPTION

4o6top is a simple tool to track the session information of IPv4 packets on IPv6 (Encapsulation)

- DS-Lite(RFC6333),MAP-E(RFC7597),LW4o6(RFC7596)

```
[Client]----[CE/B4]------+-----[BR/AFTR]-----[IPv4 Internet]
                         |
                     (capture)
```


### screen shot
![sc](https://github.com/skubota/4o6top/raw/master/media/4o6top.png)

### requrement

- golang
- libpcap (libpcap-devel)

### usage

	$ go get -u github.com/skubota/4o6top
	$ tcpdump -i eth0 -l -w - 'ip6' | 4o6top -s xxx.xxx.xxx.xxx -h 30 -Tt 60 -Tu 30 -i 1

### option

```
Usage of ./4o6top:
  -Ti int
    	ICMP Timeout (default 3)
  -Tt int
    	TCP Timeout (default 240)
  -Ttr int
    	TCP RST/FIN Timeout (default 10)
  -Tu int
    	UDP Timeout (default 60)
  -Tud int
    	UDP DNS Timeout (default 3)
  -d string
    	Field delimiter(stat,log) (default ",")
  -h int
    	Height(sum) (default 30)
  -i int
    	reflesh interval(sum,stat) (default 1)
  -m string
    	Mode [sum|stat|log] (default "sum")
  -r string
    	Read pcap file (default "-")
  -s string
    	Source ip address
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details

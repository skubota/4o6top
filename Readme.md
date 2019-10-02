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

### requrement

- golang
- - gopacket
- libpcap (libpcap-devel)

### usage

```Shell
$ go get -u github.com/skubota/4o6top
$ tcpdump -i eth0 -l -w - 'ip6' | ~/go/bin/4o6top -s xxx.xxx.xxx.xxx -h 30 -Tt 60 -Tu 30 -i 1
```

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
    	Field delimiter(stat,log,sess) (default ",")
  -h int
    	Summary table height(sum) (default 30)
  -i int
    	reflesh interval(sum,stat) (default 1)
  -m string
    	Mode [sum|stat|log|sess] (default "sum")
  -n	No header.tupples only(stat,log,sess)
  -r string
    	Read pcap file (default "-")
  -s string
    	Source ip address
```

### mode

- Summary(sum)

```
4o6top ver: 0.3
 Option file:./capture.pcap interval:1 Timeout:60/3/30/3/3 Height:30 src ip:xxx.xxx.xxx.xxx

2019/01/01 00:00:00  Total Sess:357
  TCP  Sess:   195 DstIP:    58 SrcPort:   181 DstPort:     2
  UDP  Sess:   162 DstIP:   125 SrcPort:   142 DstPort:     4
  ICMP Sess:     0 DstIP:     0 ICMP ID:     0

 Proto       Source IP: Port         Dest IP: Port    Packets      Bytes Timeout
   UDP xxx.xxx.xxx.xxx:23504  34.194.116.xxx:22222          2        100    29
   UDP xxx.xxx.xxx.xxx:31709   35.228.77.xxx:22222          2        100    29
   TCP xxx.xxx.xxx.xxx:64465  69.192.104.xxx:  443         23       9676    59
   UDP xxx.xxx.xxx.xxx:41943    35.203.2.xxx:22222          2        100    29
```

- Statistics(stat)

```
time,Session,TCPSession,UDPSession,ICMPSession,TCPSrcPort,UDPSrcPort,ICMPID,TCPDstIP,UDPDstIP,ICMPDstIP,TCPDstPort,UDPDstPort,
2019-01-01T00:00:01+09:00,0,0,0,0,0,0,0,0,0,0,0,0,
2019-01-01T00:00:02+09:00,357,195,162,0,181,142,0,58,125,0,2,4,
```

- Logging(log)

```
time,Proto,SrcIP,SrcPort,DstIP,DstPort,Length,
2019-01-01T00:00:01+09:00,TCP,xxx.xxx.xxx.xxx,37855,52.38.43.xxx,443,88
2019-01-01T00:00:01+09:00,TCP,xxx.xxx.xxx.xxx,37855,52.38.43.xxx,443,84
2019-01-01T00:00:01+09:00,TCP,xxx.xxx.xxx.xxx,37855,52.38.43.xxx,443,52
2019-01-01T00:00:02+09:00,TCP,xxx.xxx.xxx.xxx,58324,34.214.175.xxx,443,60
2019-01-01T00:00:02+09:00,TCP,xxx.xxx.xxx.xxx,13267,23.67.185.xxx,80,60
2019-01-01T00:00:02+09:00,TCP,xxx.xxx.xxx.xxx,29659,23.67.185.xxx,80,60
2019-01-01T00:00:02+09:00,TCP,xxx.xxx.xxx.xxx,13267,23.67.185.xxx,80,60
2019-01-01T00:00:02+09:00,TCP,xxx.xxx.xxx.xxx,47059,69.192.104.xxx,443,52
2019-01-01T00:00:02+09:00,TCP,xxx.xxx.xxx.xxx,13267,23.67.185.xxx,80,52
```

- Session(sess)

```
Proto,SrcIP,SrcPort,DstIP,DstPort,
TCP,xxx.xxx.xxx.xxx,37855,52.38.43.xxx,443
TCP,xxx.xxx.xxx.xxx,58324,34.214.175.xxx,443
TCP,xxx.xxx.xxx.xxx,13267,23.67.185.xxx,80
TCP,xxx.xxx.xxx.xxx,29659,23.67.185.xxx,80
TCP,xxx.xxx.xxx.xxx,47059,69.192.104.xxx,443
TCP,xxx.xxx.xxx.xxx,18389,23.67.185.xxx,443
TCP,xxx.xxx.xxx.xxx,61401,69.192.104.xxx,443
TCP,xxx.xxx.xxx.xxx,57302,23.67.187.xxx,443
TCP,xxx.xxx.xxx.xxx,53210,23.67.185.xxx,80
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details

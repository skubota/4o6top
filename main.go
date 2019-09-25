package main

import (
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Version of PROG
var Version = "0.2"

// Name of PROG
var Name = "4o6top"

// Options struct for option
type Options struct {
	srcIP     *string
	pcapFile  *string
	interval  *int
	initTTL   *int
	height    *int
	mode      *string
	count     *bool
	delimiter *string
}

// map struct for session map
type maps struct {
	sync.Mutex
	sess        map[string]string
	sessionTCP  int
	sessionUDP  int
	sessionICMP int
	srcportTCP  map[int]int
	srcportUDP  map[int]int
	srcportICMP map[int]int
	dstportTCP  map[int]int
	dstportUDP  map[int]int
	dstportICMP map[int]int
	dstipTCP    map[string]int
	dstipUDP    map[string]int
	dstipICMP   map[string]int
}

// mymap session gloval var
var mymap = maps{
	sess:        map[string]string{},
	sessionTCP:  0,
	sessionUDP:  0,
	sessionICMP: 0,
	srcportTCP:  map[int]int{},
	srcportUDP:  map[int]int{},
	srcportICMP: map[int]int{},
	dstportTCP:  map[int]int{},
	dstportUDP:  map[int]int{},
	dstportICMP: map[int]int{},
	dstipTCP:    map[string]int{},
	dstipUDP:    map[string]int{},
	dstipICMP:   map[string]int{},
}

type b4map struct {
	sessionTCP  int
	sessionUDP  int
	sessionICMP int
	srcportTCP  int
	srcportUDP  int
	srcidICMP   int
	dstportTCP  int
	dstportUDP  int
	dstipTCP    int
	dstipUDP    int
	dstipICMP   int
}

var b4 = b4map{
	sessionTCP:  0,
	sessionUDP:  0,
	sessionICMP: 0,
	srcportTCP:  0,
	srcportUDP:  0,
	srcidICMP:   0,
	dstportTCP:  0,
	dstportUDP:  0,
	dstipTCP:    0,
	dstipUDP:    0,
	dstipICMP:   0,
}

// print session table
func printSessionTable(opt Options) {
	h := *opt.height
	m := *opt.mode
	c := *opt.count

	// counter
	session := mymap.sessionTCP + mymap.sessionUDP + mymap.sessionICMP
	sessionTCP := mymap.sessionTCP
	sessionUDP := mymap.sessionUDP
	sessionICMP := mymap.sessionICMP
	srcportTCP := len(mymap.srcportTCP)
	srcportUDP := len(mymap.srcportUDP)
	srcidICMP := len(mymap.srcportICMP)
	dstipTCP := len(mymap.dstipTCP)
	dstipUDP := len(mymap.dstipUDP)
	dstipICMP := len(mymap.dstipICMP)
	dstportTCP := len(mymap.dstportTCP)
	dstportUDP := len(mymap.dstportUDP)

	if c {
		session = session - (b4.sessionTCP + b4.sessionUDP + b4.sessionICMP)
		sessionTCP = sessionTCP - b4.sessionTCP
		sessionUDP = sessionUDP - b4.sessionUDP
		sessionICMP = sessionICMP - b4.sessionICMP
		srcportTCP = srcportTCP - b4.srcportTCP
		srcportUDP = srcportUDP - b4.srcportUDP
		srcidICMP = srcidICMP - b4.srcidICMP
		dstipTCP = dstipTCP - b4.dstipTCP
		dstipUDP = dstipUDP - b4.dstipUDP
		dstipICMP = dstipICMP - b4.dstipICMP
		dstportTCP = dstportTCP - b4.dstportTCP
		dstportUDP = dstportUDP - b4.dstportUDP

		b4.sessionTCP = mymap.sessionTCP
		b4.sessionUDP = mymap.sessionUDP
		b4.sessionICMP = mymap.sessionICMP
		b4.srcportTCP = len(mymap.srcportTCP)
		b4.srcportUDP = len(mymap.srcportUDP)
		b4.srcidICMP = len(mymap.srcportICMP)
		b4.dstipTCP = len(mymap.dstipTCP)
		b4.dstipUDP = len(mymap.dstipUDP)
		b4.dstipICMP = len(mymap.dstipICMP)
		b4.dstportTCP = len(mymap.dstportTCP)
		b4.dstportUDP = len(mymap.dstportUDP)

	}
	// SUM
	if m == "sum" {
		fmt.Printf("\033[H\033[2J")
		fmt.Printf("%s ver: %s\n", Name, Version)
		fmt.Printf(" Option file:%s interval:%d TTL:%d Height:%d src ip:%s\n\n", *opt.pcapFile, *opt.interval, *opt.initTTL, *opt.height, *opt.srcIP)

		log.Printf(" Total Sess:%d\n", mymap.sessionTCP+mymap.sessionUDP+mymap.sessionICMP)
		fmt.Printf("  TCP  Sess:%6d DstIP:%6d SrcPort:%6d DstPort:%6d\n", mymap.sessionTCP, len(mymap.dstipTCP), len(mymap.srcportTCP), len(mymap.dstportTCP))
		fmt.Printf("  UDP  Sess:%6d DstIP:%6d SrcPort:%6d DstPort:%6d\n", mymap.sessionUDP, len(mymap.dstipUDP), len(mymap.srcportUDP), len(mymap.dstportUDP))
		fmt.Printf("  ICMP Sess:%6d DstIP:%6d SrcPort:%6d ICMP ID:%6d\n", mymap.sessionICMP, len(mymap.dstipICMP), len(mymap.srcportICMP), len(mymap.dstportICMP))

		fmt.Printf("\n%6s %15s:%5s %15s:%5s %10s %10s %5s\n", "Proto", "Source IP", "Port", "Dest IP", "Port", "Packets", "Bytes", "ViewTTL")
	}
	if m == "stat" {
		t := time.Now()
		d := *opt.delimiter
		//time,Session,TCPSession,UDPSession,ICMPSession,TCPSrcPort,UDPSrcPort,ICMPId,TCPDstPort,UDPDstPort
		fmt.Printf("%s%s", t.Format(time.RFC3339Nano), d)
		fmt.Printf("%d%s", session, d)
		fmt.Printf("%d%s", sessionTCP, d)
		fmt.Printf("%d%s", sessionUDP, d)
		fmt.Printf("%d%s", sessionICMP, d)
		fmt.Printf("%d%s", srcportTCP, d)
		fmt.Printf("%d%s", srcportUDP, d)
		fmt.Printf("%d%s", srcidICMP, d)
		fmt.Printf("%d%s", dstipTCP, d)
		fmt.Printf("%d%s", dstipUDP, d)
		fmt.Printf("%d%s", dstipICMP, d)
		fmt.Printf("%d%s", dstportTCP, d)
		fmt.Printf("%d%s", dstportUDP, d)
		fmt.Printf("\n")
	}
	tmp := mymap.sess
	for k, v := range tmp {
		var pkt int64
		var byte int64
		var ttl int64
		if len(v) > 0 {
			val := strings.Split(v, ",")
			if len(val[0]) > 0 {
				pkt, _ = strconv.ParseInt(val[0], 10, 64)
			}
			if len(val[1]) > 0 {
				byte, _ = strconv.ParseInt(val[1], 10, 64)
			}
			if len(val[2]) > 0 {
				ttl, _ = strconv.ParseInt(val[2], 10, 64)
			}

			ttl--
			h--

			if ttl > 0 {
				mymap.Lock()
				mymap.sess[k] = fmt.Sprintf("%d,%d,%d", pkt, byte, ttl)
				mymap.Unlock()
				if m == "sum" {
					fmt.Printf("%s %10d %10d %5d\n", k, pkt, byte, ttl)
				}

			} else {
				mymap.Lock()
				delete(mymap.sess, k)
				mymap.Unlock()
			}

		}
		if h < 2 {
			return
		}
	}
}

// capture packet
func capturePacket(packet gopacket.Packet, opt Options) {
	l := packet.Layer(layers.LayerTypeIPv6)
	m := *opt.mode

	if l != nil {
		ip6, _ := l.(*layers.IPv6)
		if ip6.NextHeader == layers.IPProtocolIPv4 {
			rev := false
			var (
				Proto, SrcIP, DstIP string
			)
			var (
				SrcPort, DstPort int
			)
			var Length int64
			nl := packet.Layer(layers.LayerTypeIPv4)
			ip4, _ := nl.(*layers.IPv4)

			SrcIP = fmt.Sprintf("%s", ip4.SrcIP)
			DstIP = fmt.Sprintf("%s", ip4.DstIP)

			if DstIP == *opt.srcIP {
				SrcIP = fmt.Sprintf("%s", ip4.DstIP)
				DstIP = fmt.Sprintf("%s", ip4.SrcIP)
				rev = true
			}
			Length = int64(ip6.Length)
			if ip4.Protocol == layers.IPProtocolTCP {
				Proto = "TCP"
				tl := packet.Layer(layers.LayerTypeTCP)
				tcp, ret := tl.(*layers.TCP)
				if ret == false {
					return
				}
				if rev {
					SrcPort = int(tcp.DstPort)
					DstPort = int(tcp.SrcPort)
				} else {
					SrcPort = int(tcp.SrcPort)
					DstPort = int(tcp.DstPort)
				}
				mymap.Lock()
				mymap.dstipTCP[DstIP] = 1
				mymap.dstportTCP[DstPort] = 1
				mymap.srcportTCP[SrcPort] = 1
				mymap.sessionTCP++
				mymap.Unlock()
			}
			if ip4.Protocol == layers.IPProtocolUDP {
				Proto = "UDP"
				ul := packet.Layer(layers.LayerTypeUDP)
				udp, ret := ul.(*layers.UDP)
				if ret == false {
					return
				}
				if rev {
					SrcPort = int(udp.DstPort)
					DstPort = int(udp.SrcPort)
				} else {
					SrcPort = int(udp.SrcPort)
					DstPort = int(udp.DstPort)
				}
				mymap.Lock()
				mymap.dstipUDP[DstIP] = 1
				mymap.dstportUDP[DstPort] = 1
				mymap.srcportUDP[SrcPort] = 1
				mymap.sessionUDP++
				mymap.Unlock()
			}
			if ip4.Protocol == layers.IPProtocolICMPv4 {
				Proto = "ICMP"
				il := packet.Layer(layers.LayerTypeICMPv4)
				icmp, ret := il.(*layers.ICMPv4)
				if ret == false {
					return
				}
				SrcPort = int(icmp.Id)
				DstPort = int(icmp.Id)
				mymap.Lock()
				mymap.dstipICMP[DstIP] = 1
				mymap.dstportICMP[DstPort] = 1
				mymap.srcportICMP[SrcPort] = 1
				mymap.sessionICMP++
				mymap.Unlock()
			}
			entry := fmt.Sprintf("%6s %15s:%5d %15s:%5d", Proto, SrcIP, SrcPort, DstIP, DstPort)

			var pkt int64
			var byte int64
			var ttl = int64(*opt.initTTL)

			mymap.Lock()
			_, ok := mymap.sess[entry]
			mymap.Unlock()
			if ok {
				mymap.Lock()
				val := strings.Split(mymap.sess[entry], ",")
				mymap.Unlock()
				pkt, _ = strconv.ParseInt(val[0], 10, 64)
				byte, _ = strconv.ParseInt(val[1], 10, 64)
				ttl, _ = strconv.ParseInt(val[2], 10, 64)
				ttl--
			}
			if m == "log" {
				t := packet.Metadata().CaptureInfo.Timestamp
				d := *opt.delimiter
				fmt.Printf("%s%s%s%s%s%s%d%s%s%s%d%s%d\n", t.Format(time.RFC3339Nano), d, Proto, d, SrcIP, d, SrcPort, d, DstIP, d, DstPort, d, Length)
			}
			mymap.Lock()
			mymap.sess[entry] = fmt.Sprintf("%d,%d,%d", pkt+1, byte+Length, ttl)
			mymap.Unlock()
		}
	}
}

// main func
func main() {
	opt := new(Options)

	opt.mode = flag.String("m", "sum", "Mode [sum|stat|log]")

	opt.srcIP = flag.String("s", "", "Source ip address")
	opt.pcapFile = flag.String("r", "-", "Read pcap file")

	opt.initTTL = flag.Int("t", 3, "Entry view ttl(sum)")
	opt.height = flag.Int("h", 30, "Height(sum)")

	opt.delimiter = flag.String("d", ",", "Field delimiter(stat,log)")
	opt.interval = flag.Int("i", 1, "reflesh interval(sum,stat)")
	opt.count = flag.Bool("c", true, "Counter refresh every interval(sum,stat)")
	flag.Parse()

	// open pcap file
	handle, err := pcap.OpenOffline(*opt.pcapFile)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// header
	d := *opt.delimiter
	if *opt.mode == "log" {
		fmt.Printf("time%s", d)
		fmt.Printf("Proto%s", d)
		fmt.Printf("SrcIP%s", d)
		fmt.Printf("SrcPort%s", d)
		fmt.Printf("DstIP%s", d)
		fmt.Printf("DstPort%s", d)
		fmt.Printf("Length%s", d)
		fmt.Printf("\n")
	}
	if *opt.mode == "stat" {
		fmt.Printf("time%s", d)
		fmt.Printf("Session%s", d)
		fmt.Printf("TCPSession%s", d)
		fmt.Printf("UDPSession%s", d)
		fmt.Printf("ICMPSession%s", d)
		fmt.Printf("TCPSrcPort%s", d)
		fmt.Printf("UDPSrcPort%s", d)
		fmt.Printf("ICMPID%s", d)
		fmt.Printf("TCPDstIP%s", d)
		fmt.Printf("UDPDstIP%s", d)
		fmt.Printf("ICMPDstIP%s", d)
		fmt.Printf("TCPDstPort%s", d)
		fmt.Printf("UDPDstPort%s", d)
		fmt.Printf("\n")
	}

	// capture routine
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	go func(opt Options) {
		for {
			packet, err := packetSource.NextPacket()
			if err == io.EOF {
				break
			} else if err != nil {
				log.Println("Error:", err)
				continue
			}
			capturePacket(packet, opt)
		}
		// exit buffer
		time.Sleep(1 * time.Second)
		os.Exit(0)
	}(*opt)

	// print loop
	for {
		printSessionTable(*opt)
		time.Sleep(time.Duration(*opt.interval) * time.Second)
	}
}

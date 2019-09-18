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
	srcIP    *string
	pcapFile *string
	interval *int
	initTTL  *int
	height   *int
	stat     *bool
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

// print session table
func printSessionTable(opt Options) {
	h := *opt.height

	fmt.Printf("\033[H\033[2J")
	fmt.Printf("%s ver: %s\n", Name, Version)
	fmt.Printf(" Option file:%s interval:%d TTL:%d Height:%d src ip:%s\n\n", *opt.pcapFile, *opt.interval, *opt.initTTL, *opt.height, *opt.srcIP)

	log.Printf(" Total Sessions %d\n", mymap.sessionTCP+mymap.sessionUDP+mymap.sessionICMP)
	fmt.Printf("  TCP  Sessions:%6d DstIP:%6d SrcPort:%6d DstPort:%6d\n", mymap.sessionTCP, len(mymap.dstipTCP), len(mymap.srcportTCP), len(mymap.dstportTCP))
	fmt.Printf("  UDP  Sessions:%6d DstIP:%6d SrcPort:%6d DstPort:%6d\n", mymap.sessionUDP, len(mymap.dstipUDP), len(mymap.srcportUDP), len(mymap.dstportUDP))
	fmt.Printf("  ICMP Sessions:%6d DstIP:%6d SrcPort:%6d DstPort:%6d\n", mymap.sessionICMP, len(mymap.dstipICMP), len(mymap.srcportICMP), len(mymap.dstportICMP))

	fmt.Printf("\n%6s %15s:%5s %15s:%5s %10s %10s %5s\n", "Proto", "Source IP", "Port", "Dest IP", "Port", "Packets", "Bytes", "ViewTTL")
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
				fmt.Printf("%s %10d %10d %5d\n", k, pkt, byte, ttl)

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

			_, ok := mymap.sess[entry]
			if ok {
				val := strings.Split(mymap.sess[entry], ",")
				pkt, _ = strconv.ParseInt(val[0], 10, 64)
				byte, _ = strconv.ParseInt(val[1], 10, 64)
				ttl, _ = strconv.ParseInt(val[2], 10, 64)
				ttl--
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
	opt.srcIP = flag.String("s", "", "source ip address")
	opt.pcapFile = flag.String("r", "-", "Read pcap file")
	opt.interval = flag.Int("i", 1, "reflesh interval")
	opt.initTTL = flag.Int("t", 3, "entry view ttl")
	opt.height = flag.Int("h", 30, "height")
	opt.stat = flag.Bool("S", false, "statistics mode")
	// flag parse
	flag.Parse()

	// open pcap file
	handle, err := pcap.OpenOffline(*opt.pcapFile)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

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

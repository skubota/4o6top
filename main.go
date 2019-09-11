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

// Global var
var (
	// Version of PROG
	Version  string
	srcIP    = flag.String("s", "", "source ip address")
	pcapFile = flag.String("r", "-", "Read pcap file")
	interval = flag.Int("i", 1, "reflesh interval")
	initTTL  = flag.Int("t", 3, "entry view ttl")
	height   = flag.Int("h", 30, "height")
 	stat   = flag.Bool("S", false, "statistics mode")

	sessionTCP  int
	sessionUDP  int
	sessionICMP int
	srcportTCP  = make(map[int]int)
	srcportUDP  = make(map[int]int)
	srcportICMP = make(map[int]int)
	dstportTCP  = make(map[int]int)
	dstportUDP  = make(map[int]int)
	dstportICMP = make(map[int]int)
	dstipTCP    = make(map[string]int)
	dstipUDP    = make(map[string]int)
	dstipICMP   = make(map[string]int)
)

// map struct
type maps struct {
	sync.Mutex
	sess map[string]string
}

// mymap
var mymap = maps{
	sess: map[string]string{},
}

// print session table
func printSessionTable() {
	h := *height
	fmt.Printf("\033[H\033[2J")
	fmt.Printf("4o6top ver: %s\n", Version)
	fmt.Printf(" Option file:%s interval:%d TTL:%d Height:%d src ip:%s\n", *pcapFile, *interval, *initTTL, *height, *srcIP)
	log.Printf(" Sessions %d\n", sessionTCP+sessionUDP+sessionICMP)
	fmt.Printf("  TCP  Sessions:%6d SrcPort:%6d DstIP:%6d DstPort:%6d\n", sessionTCP, len(srcportTCP), len(dstipTCP), len(dstportTCP))
	fmt.Printf("  UDP  Sessions:%6d SrcPort:%6d DstIP:%6d DstPort:%6d\n", sessionUDP, len(srcportUDP), len(dstipUDP), len(dstportUDP))
	fmt.Printf("  ICMP Sessions:%6d SrcPort:%6d DstIP:%6d DstPort:%6d\n", sessionICMP, len(srcportICMP), len(dstipICMP), len(dstportICMP))
	fmt.Printf("\n%6s %15s:%5s -> %15s:%5s %10s %10s %5s\n", "Proto", "Source IP", "Port", "Dest IP", "Port", "Packets", "Bytes","ViewTTL")
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
			fmt.Printf("%s %10d %10d %5d\n", k, pkt, byte,ttl)
			}else{
				mymap.Lock()
				delete(mymap.sess, k)
				mymap.Unlock()
			}

		}
		if h < 2 {
			return
		}
	}
	sessionTCP = 0
	sessionUDP = 0
	sessionICMP = 0
	srcportTCP = make(map[int]int)
	srcportUDP = make(map[int]int)
	srcportICMP = make(map[int]int)
	dstportTCP = make(map[int]int)
	dstportUDP = make(map[int]int)
	dstportICMP = make(map[int]int)
	dstipTCP = make(map[string]int)
	dstipUDP = make(map[string]int)
	dstipICMP = make(map[string]int)
}

// capture packet
func capturePacket(packet gopacket.Packet) {
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

			if DstIP == *srcIP {
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
				dstipTCP[DstIP] = 1
				dstportTCP[DstPort] = 1
				srcportTCP[SrcPort] = 1
				sessionTCP++
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
				dstipUDP[DstIP] = 1
				dstportUDP[DstPort] = 1
				srcportUDP[SrcPort] = 1
				sessionUDP++
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
				dstipICMP[DstIP] = 1
				dstportICMP[DstPort] = 1
				srcportICMP[SrcPort] = 1
				sessionICMP++
			}
			entry := fmt.Sprintf("%6s %15s:%5d -> %15s:%5d", Proto, SrcIP, SrcPort, DstIP, DstPort)

			var pkt int64
			var byte int64
			var ttl = int64(*initTTL)

			_, ok := mymap.sess[entry]
			if ok {
				val := strings.Split(mymap.sess[entry], ",")
				pkt, _ = strconv.ParseInt(val[0], 10, 64)
				byte, _ = strconv.ParseInt(val[1], 10, 64)
				ttl, _ = strconv.ParseInt(val[2], 10, 64)
				ttl--
			}
			if ttl <= 0 {
				mymap.Lock()
				delete(mymap.sess, entry)
				mymap.Unlock()
			} else {
				mymap.Lock()
				mymap.sess[entry] = fmt.Sprintf("%d,%d,%d", pkt+1, byte+Length, ttl)
				mymap.Unlock()
			}
		}
	}
}

// main func
func main() {
	// flag parse
	flag.Parse()

	// open pcap file
	handle, err := pcap.OpenOffline(*pcapFile)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// capture routine
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	go func() {
		for {
			packet, err := packetSource.NextPacket()
			if err == io.EOF {
				break
			} else if err != nil {
				log.Println("Error:", err)
				continue
			}
			capturePacket(packet)
		}
		// exit buffer
		time.Sleep(1 * time.Second)
		os.Exit(0)
	}()

	// print loop
	for {
		printSessionTable()
		time.Sleep(time.Duration(*interval) * time.Second)
	}
}

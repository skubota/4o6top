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

var (
	pcapFile = flag.String("r", "-", "Read pcap file")
	interval = flag.Int("i", 1, "reflesh interval")
	initTTL  = flag.Int("t", 3, "entry view ttl")
	height   = flag.Int("h", 30, "height")

	sortKey = make(map[int]string)
	handle  *pcap.Handle
	err     error
)

type maps struct {
	sync.Mutex
	sess map[string]string
}

var mymap = maps{
	sess: map[string]string{},
}

func printSessionTable(h int) {
	fmt.Printf("\033[H\033[2J%6s %15s:%5s -> %15s:%5s %10s %10s\n", "Proto", "Source IP", "Port", "Dest IP", "Port", "Packet", "Bytes")
	mymap.Lock()
	tmp := mymap.sess
	mymap.Unlock()
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

			mymap.Lock()
			mymap.sess[k] = fmt.Sprintf("%d,%d,%d", pkt, byte, ttl)
			mymap.Unlock()
			if len(val[0]) > 0 && len(val[1]) > 0 {
				fmt.Printf("%s %10s %10s\n", k, val[0], val[1])
			}

			if ttl <= 0 {
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

func capturePacket(packet gopacket.Packet) {
	l := packet.Layer(layers.LayerTypeIPv6)
	if l != nil {
		ip6, _ := l.(*layers.IPv6)
		if ip6.NextHeader == layers.IPProtocolIPv4 {
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
			Length = int64(ip6.Length)
			if ip4.Protocol == layers.IPProtocolTCP {
				Proto = "TCP"
				tl := packet.Layer(layers.LayerTypeTCP)
				tcp, ret := tl.(*layers.TCP)
				if ret == false {
					return
				}
				SrcPort = int(tcp.SrcPort)
				DstPort = int(tcp.DstPort)
			}
			if ip4.Protocol == layers.IPProtocolUDP {
				Proto = "UDP"
				ul := packet.Layer(layers.LayerTypeUDP)
				udp, ret := ul.(*layers.UDP)
				if ret == false {
					return
				}
				SrcPort = int(udp.SrcPort)
				DstPort = int(udp.DstPort)
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
			}
			entry := fmt.Sprintf("%6s %15s:%5d -> %15s:%5d", Proto, SrcIP, SrcPort, DstIP, DstPort)

			var pkt int64
			var byte int64
			var ttl = int64(*initTTL)

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
				ttl++
			}
			mymap.Lock()
			mymap.sess[entry] = fmt.Sprintf("%d,%d,%d", pkt+1, byte+Length, ttl)
			mymap.Unlock()
		}
	}
}

func main() {
	flag.Parse()
	handle, err = pcap.OpenOffline(*pcapFile)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

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
		time.Sleep(1 * time.Second)
		os.Exit(0)
	}()
	for {
		printSessionTable(*height)
		time.Sleep(time.Duration(*interval) * time.Second)
	}
}

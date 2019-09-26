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
	delimiter *string
}

// map struct for session map
type maps struct {
	sync.Mutex
	sess map[string]string
}

// mymap session gloval var
var mymap = maps{
	sess: map[string]string{},
}

// print session table
func printSessionTable(opt Options) {
	h := *opt.height
	m := *opt.mode

	// counter
	srcport := make(map[string]map[string]int)
	srcport["TCP"] = make(map[string]int)
	srcport["UDP"] = make(map[string]int)
	srcport["ICMP"] = make(map[string]int)

	dstip := make(map[string]map[string]int)
	dstip["TCP"] = make(map[string]int)
	dstip["UDP"] = make(map[string]int)
	dstip["ICMP"] = make(map[string]int)

	dstport := make(map[string]map[string]int)
	dstport["TCP"] = make(map[string]int)
	dstport["UDP"] = make(map[string]int)

	session := make(map[string]map[string]int)
	session["TCP"] = make(map[string]int)
	session["UDP"] = make(map[string]int)
	session["ICMP"] = make(map[string]int)

	// now session
	mymap.Lock()
	tmp := mymap.sess
	mymap.Unlock()
	for k := range tmp {
		// ss=[Proto, SrcIP, SrcPort, DstIP, DstPort]
		ss := strings.Split(k, ",")
		if ss[0] == "TCP" {
			srcport["TCP"][ss[2]] = 1
			dstip["TCP"][ss[3]] = 1
			dstport["TCP"][ss[4]] = 1
			session["TCP"][ss[2]+":"+ss[3]+":"+ss[4]] = 1
		}
		if ss[0] == "UDP" {
			srcport["UDP"][ss[2]] = 1
			dstip["UDP"][ss[3]] = 1
			dstport["UDP"][ss[4]] = 1
			session["UDP"][ss[2]+":"+ss[3]+":"+ss[4]] = 1
		}
		if ss[0] == "ICMP" {
			srcport["ICMP"][ss[2]] = 1
			dstip["ICMP"][ss[3]] = 1
			session["ICMP"][ss[2]+":"+ss[3]+":"+ss[4]] = 1
		}
	}

	sessions := len(session["TCP"]) + len(session["UDP"]) + len(session["ICMP"])

	// summary mode
	if m == "sum" {
		fmt.Printf("\033[H\033[2J")
		fmt.Printf("%s ver: %s\n", Name, Version)
		fmt.Printf(" Option file:%s interval:%d TTL:%d Height:%d src ip:%s\n\n", *opt.pcapFile, *opt.interval, *opt.initTTL, *opt.height, *opt.srcIP)

		log.Printf(" Total Sess:%d\n", sessions)
		fmt.Printf("  TCP  Sess:%6d DstIP:%6d SrcPort:%6d DstPort:%6d\n", len(session["TCP"]), len(dstip["TCP"]), len(srcport["TCP"]), len(dstport["TCP"]))
		fmt.Printf("  UDP  Sess:%6d DstIP:%6d SrcPort:%6d DstPort:%6d\n", len(session["UDP"]), len(dstip["UDP"]), len(srcport["UDP"]), len(dstport["UDP"]))
		fmt.Printf("  ICMP Sess:%6d DstIP:%6d ICMP ID:%6d\n", len(session["ICMP"]), len(dstip["ICMP"]), len(srcport["ICMP"]))

		fmt.Printf("\n%6s %15s:%5s %15s:%5s %10s %10s %5s\n", "Proto", "Source IP", "Port", "Dest IP", "Port", "Packets", "Bytes", "ViewTTL")
	}
	// statistics mode
	if m == "stat" {
		t := time.Now()
		d := *opt.delimiter
		//time,Session,TCPSession,UDPSession,ICMPSession,TCPSrcPort,UDPSrcPort,ICMPId,TCPDstPort,UDPDstPort
		fmt.Printf("%s%s", t.Format(time.RFC3339Nano), d)
		fmt.Printf("%d%s", sessions, d)
		fmt.Printf("%d%s", len(session["TCP"]), d)
		fmt.Printf("%d%s", len(session["UDP"]), d)
		fmt.Printf("%d%s", len(session["ICMP"]), d)
		fmt.Printf("%d%s", len(srcport["TCP"]), d)
		fmt.Printf("%d%s", len(srcport["UDP"]), d)
		fmt.Printf("%d%s", len(srcport["ICMP"]), d)
		fmt.Printf("%d%s", len(dstip["TCP"]), d)
		fmt.Printf("%d%s", len(dstip["UDP"]), d)
		fmt.Printf("%d%s", len(dstip["ICMP"]), d)
		fmt.Printf("%d%s", len(dstport["TCP"]), d)
		fmt.Printf("%d%s", len(dstport["UDP"]), d)
		fmt.Printf("\n")
	}
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

			// ss=[Proto, SrcIP, SrcPort, DstIP, DstPort]
			ss := strings.Split(k, ",")
			if ttl > 0 {
				mymap.Lock()
				mymap.sess[k] = fmt.Sprintf("%d,%d,%d", pkt, byte, ttl)
				mymap.Unlock()
				if m == "sum" {
					fmt.Printf("%6s %15s:%5s %15s:%5s %10d %10d %5d\n", ss[0], ss[1], ss[2], ss[3], ss[4], pkt, byte, ttl)
				}

			} else {
				mymap.Lock()
				delete(mymap.sess, k)
				mymap.Unlock()
			}
		}
		if h < 1 {
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
			entry := fmt.Sprintf("%s,%s,%d,%s,%d", Proto, SrcIP, SrcPort, DstIP, DstPort)

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
				//ttl--
			}
			// logging mode
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

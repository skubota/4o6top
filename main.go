package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/olivere/elastic"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Name of PROG
var Name = "4o6top"

// Version of PROG
var Version = "0.4"

// Options struct for option
type Options struct {
	srcIP         *string
	pcapFile      *string
	interval      *int
	height        *int
	mode          *string
	delimiter     *string
	timeOutTCP    *int
	timeOutTCPRst *int
	timeOutUDP    *int
	timeOutUDPDns *int
	timeOutICMP   *int
	noheader      *bool
	endpoint      *string
}

// ELstat structure
type ELstat struct {
	Mode         string `json:"mode"`
	Timestamp    string `json:"timestamp"`
	TotalSession int    `json:"total_session"`
	TCPSession   int    `json:"tcp_session"`
	UDPSession   int    `json:"udp_session"`
	ICMPSession  int    `json:"icmp_session"`
	TCPSrcPort   int    `json:"tcp_src_port"`
	UDPSrcPort   int    `json:"udp_src_port"`
	ICMPID       int    `json:"icmp_id"`
	TCPDstIP     int    `json:"tcp_dst_ip"`
	UDPDstIP     int    `json:"udp_dst_ip"`
	ICMPDstIP    int    `json:"icmp_dst_ip"`
	TCPDstPort   int    `json:"tcp_dst_port"`
	UDPDstPort   int    `json:"udp_dst_port"`
}

// ELsess structure
type ELsess struct {
	Mode                 string `json:"mode"`
	Timestamp            string `json:"timestamp"`
	Protocol             string `json:"protocol"`
	SourceIpAddress      string `json:"source_ip_address"`
	SourcePort           int    `json:"source_port"`
	DestinationIpAddress string `json:"destination_ip_address"`
	DestinationPort      int    `json:"destination_port"`
}

// session gloval var map
var sess sync.Map

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
	sess.Range(func(k, v interface{}) bool {
		// ss=[Proto, SrcIP, SrcPort, DstIP, DstPort]
		ss := strings.Split(fmt.Sprintf("%s", k), ",")
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
		return true
	})

	sessions := len(session["TCP"]) + len(session["UDP"]) + len(session["ICMP"])

	// summary mode
	if m == "sum" {
		fmt.Printf("\033[H\033[2J")
		fmt.Printf("%s ver: %s\n", Name, Version)
		fmt.Printf(" Option file:%s interval:%d Timeout:%d/%d/%d/%d/%d Height:%d src ip:%s\n\n", *opt.pcapFile, *opt.interval, *opt.timeOutTCP, *opt.timeOutTCPRst, *opt.timeOutUDP, *opt.timeOutUDPDns, *opt.timeOutICMP, *opt.height, *opt.srcIP)

		log.Printf(" Total Sess:%d\n", sessions)
		fmt.Printf("  TCP  Sess:%6d DstIP:%6d SrcPort:%6d DstPort:%6d\n", len(session["TCP"]), len(dstip["TCP"]), len(srcport["TCP"]), len(dstport["TCP"]))
		fmt.Printf("  UDP  Sess:%6d DstIP:%6d SrcPort:%6d DstPort:%6d\n", len(session["UDP"]), len(dstip["UDP"]), len(srcport["UDP"]), len(dstport["UDP"]))
		fmt.Printf("  ICMP Sess:%6d DstIP:%6d ICMP ID:%6d\n", len(session["ICMP"]), len(dstip["ICMP"]), len(srcport["ICMP"]))

		fmt.Printf("\n%6s %15s:%5s %15s:%5s %10s %10s %5s\n", "Proto", "Source IP", "Port", "Dest IP", "Port", "Packets", "Bytes", "Timeout")
	}
	// statistics mode
	if m == "stat" {
		t := time.Now()
		d := *opt.delimiter
		//time,Session,TCPSession,UDPSession,ICMPSession,TCPSrcPort,UDPSrcPort,ICMPId,TCPDstPort,UDPDstPort
		fmt.Printf("%s%s", t.Format(time.RFC3339), d)
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
	// elastic mode
	if m == "elastic" {
		t := time.Now()
		// Create an index.
		indexName := fmt.Sprintf("4o6top-%s", time.Now().Format("2006-01-02"))
		// context
		ctxb := context.Background()

		// connect ES
		bulk := connectToElastic(*opt.endpoint).
			Bulk().
			Index(indexName).
			Type("stat")
		id := fmt.Sprintf("%s", t.Format(time.RFC3339))

		if bulk == nil {
			log.Fatalf("Error: HandleRequest() connectToElastic")
		}

		doc := &ELstat{
			Mode:         "stat",
			Timestamp:    t.Format(time.RFC3339),
			TotalSession: sessions,
			TCPSession:   len(session["TCP"]),
			UDPSession:   len(session["UDP"]),
			ICMPSession:  len(session["ICMP"]),
			TCPSrcPort:   len(srcport["TCP"]),
			UDPSrcPort:   len(srcport["UDP"]),
			ICMPID:       len(srcport["ICMP"]),
			TCPDstIP:     len(dstip["TCP"]),
			UDPDstIP:     len(dstip["UDP"]),
			ICMPDstIP:    len(dstip["ICMP"]),
			TCPDstPort:   len(dstport["TCP"]),
			UDPDstPort:   len(dstport["UDP"]),
		}
		bulk.Add(elastic.NewBulkIndexRequest().Doc(doc).Id(id))
		if _, err := bulk.Do(ctxb); err != nil {
			log.Fatalf("Error: HandleRequest() bulk.Do %s", err)
		}

	}

	sess.Range(func(k, v interface{}) bool {
		var pkt int64
		var byte int64
		var ttl int64
		val := strings.Split(fmt.Sprintf("%s", v), ",")
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
		ss := strings.Split(fmt.Sprintf("%s", k), ",")
		if ttl > 0 {
			sess.Store(k, fmt.Sprintf("%d,%d,%d", pkt, byte, ttl))
			if m == "sum" {
				fmt.Printf("%6s %15s:%5s %15s:%5s %10d %10d %5d\n", ss[0], ss[1], ss[2], ss[3], ss[4], pkt, byte, ttl)
			}

		} else {
			sess.Delete(k)
		}
		if h < 1 {
			return false
		}
		return true
	})
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
				SrcPort, DstPort, ttl int
			)
			var (
				Length, pkt, byte int64
			)

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
				ttl = *opt.timeOutTCP
				if tcp.RST || (tcp.FIN && tcp.ACK) {
					ttl = *opt.timeOutTCPRst
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
				ttl = *opt.timeOutUDP
				if SrcPort == 53 || DstPort == 53 {
					ttl = *opt.timeOutUDPDns
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
				ttl = *opt.timeOutICMP
			}
			entry := fmt.Sprintf("%s,%s,%d,%s,%d", Proto, SrcIP, SrcPort, DstIP, DstPort)

			if vv, ok := sess.Load(entry); ok {
				val := strings.Split(fmt.Sprintf("%s", vv), ",")
				pkt, _ = strconv.ParseInt(val[0], 10, 64)
				byte, _ = strconv.ParseInt(val[1], 10, 64)
				b4ttl, _ := strconv.Atoi(val[2])
				max := ttl
				ttl = ttl + b4ttl
				if ttl > max {
					ttl = max
				}
			} else if m == "sess" {
				d := *opt.delimiter
				fmt.Printf("%s%s%s%s%d%s%s%s%d\n", Proto, d, SrcIP, d, SrcPort, d, DstIP, d, DstPort)
			}

			// logging mode
			if m == "log" {
				t := packet.Metadata().CaptureInfo.Timestamp
				d := *opt.delimiter
				fmt.Printf("%s%s%s%s%s%s%d%s%s%s%d%s%d\n", t.Format(time.RFC3339), d, Proto, d, SrcIP, d, SrcPort, d, DstIP, d, DstPort, d, Length)
			}
			sess.Store(entry, fmt.Sprintf("%d,%d,%d", pkt+1, byte+Length, ttl))
		}
	}
}

// connect ESS
func connectToElastic(endpoint string) *elastic.Client {
	if len(endpoint) > 0 {
		for i := 0; i < 3; i++ {
			elasticClient, err := elastic.NewClient(
				elastic.SetURL(endpoint),
				elastic.SetSniff(false),
			)
			if err != nil {
				log.Fatalf("Error: connectToElastic() elastic.NewClient %s", err)
				//time.Sleep(3 * time.Second)
			} else {
				return elasticClient
			}
		}
	}
	return nil
}

// main func
func main() {
	opt := new(Options)

	flag.Usage = func() {
		usageTxt := `
Usage: 4o6top [option]

  -m string
    	Mode [sum|stat|log|sess|elastic] (default "sum")
  -r string
    	Read pcap file (default "-")
  -s string
    	Source ip address

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

 For stat,log,sess modes
  -d string
    	Field delimiter
  -n	No header.tupples only

 For sum,stat modes
  -i int
    	reflesh interval (default 1)

 For sum mode
  -h int
    	Summary table height (default 30)

 For elastic mode
  -E string
	Elastic Endpoint
`
		fmt.Fprintf(os.Stderr, "%s\n", usageTxt)
	}
	opt.mode = flag.String("m", "sum", "Mode [sum|stat|log|sess]")
	opt.endpoint = flag.String("E", "localhost", "Elastic Endpoint")

	opt.srcIP = flag.String("s", "", "Source ip address")
	opt.pcapFile = flag.String("r", "-", "Read pcap file")

	opt.timeOutTCP = flag.Int("Tt", 240, "TCP Timeout")
	opt.timeOutTCPRst = flag.Int("Ttr", 10, "TCP RST/FIN Timeout")
	opt.timeOutUDP = flag.Int("Tu", 60, "UDP Timeout")
	opt.timeOutUDPDns = flag.Int("Tud", 3, "UDP DNS Timeout")
	opt.timeOutICMP = flag.Int("Ti", 3, "ICMP Timeout")

	opt.height = flag.Int("h", 30, "Summary table height(sum)")
	opt.noheader = flag.Bool("n", false, "No header.tupples only(stat,log,sess)")

	opt.delimiter = flag.String("d", ",", "Field delimiter(stat,log,sess)")
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

	if !*opt.noheader {
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
		if *opt.mode == "sess" {
			fmt.Printf("Proto%s", d)
			fmt.Printf("SrcIP%s", d)
			fmt.Printf("SrcPort%s", d)
			fmt.Printf("DstIP%s", d)
			fmt.Printf("DstPort%s", d)
			fmt.Printf("\n")
		}
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

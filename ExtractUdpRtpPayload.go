package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/miekg/pcap"
)

var flagInFile string
var flagRTP bool

func init() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s -i IN_FILE [-r]\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.StringVar(&flagInFile, "i", "", "PCAP file")
	flag.BoolVar(&flagRTP, "r", false, "RTP feed")
}

func main() {
	flag.Parse()
	Destinations := make(map[string]*os.File)
	fmt.Println(os.Args)
	h, _ := pcap.OpenOffline(flagInFile)

	for pkt := h.Next(); pkt != nil; pkt = h.Next() {
		pkt.Decode()
		if len(pkt.Headers) >= 2 {
			ipH, ipOK := pkt.Headers[0].(*pcap.Iphdr)
			udpH, udpOK := pkt.Headers[1].(*pcap.Udphdr)
			if ipOK && udpOK {
				dumpFileName := fmt.Sprintf("Dump_%d.%d.%d.%d_%d.ts", ipH.DestIp[0],
					ipH.DestIp[1],
					ipH.DestIp[2],
					ipH.DestIp[3],
					udpH.DestPort)
				f, ok := Destinations[dumpFileName]
				if !ok {
					fmt.Println("Creating new TS file", dumpFileName)
					Destinations[dumpFileName], _ = os.Create(dumpFileName)
					f, _ = Destinations[dumpFileName]
				}
				offset := 0
				if flagRTP {
					offset = 12
				}

				f.Write(pkt.Payload[offset:])
			}
		}
	}
	for _, fileHandle := range Destinations {
		fileHandle.Close()
	}
}

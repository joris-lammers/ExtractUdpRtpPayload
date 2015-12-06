package main

import (
	"fmt"
	"os"

	"github.com/miekg/pcap"
)

func main() {
	Destinations := make(map[string]*os.File)
	fmt.Println(os.Args)
	for _, f := range os.Args[1:len(os.Args)] {
		h, _ := pcap.OpenOffline(f)

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
					f.Write(pkt.Payload)
				}
			}
		}
	}
	for _, fileHandle := range Destinations {
		fileHandle.Close()
	}
}

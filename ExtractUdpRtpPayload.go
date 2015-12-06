package main

import (
	"fmt"
	"os"
	"pcap"
)

func main() {
	var Destinations map[string]*os.File = make(map[string]*os.File)
	fmt.Println(os.Args)
	for _, f := range os.Args[1 : len(os.Args)] {
		h, _ := pcap.Openoffline(f)

		for pkt := h.Next(); pkt != nil; pkt = h.Next() {
			pkt.Decode()
			if pkt.UDP != nil {
				dumpFileName := fmt.Sprintf("Dump_%d.%d.%d.%d_%d.ts", pkt.IP.DestIp[0],
					pkt.IP.DestIp[1],
					pkt.IP.DestIp[2],
					pkt.IP.DestIp[3],
					pkt.UDP.DestPort)
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
	for _, fileHandle := range Destinations {
		fileHandle.Close()
	}
}

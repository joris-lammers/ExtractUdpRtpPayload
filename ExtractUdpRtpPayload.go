package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
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
	f, err := os.Open(flagInFile)
	if err != nil {
		fmt.Printf("Error opening file '%s': %s\n", flagInFile, err)
		return
	}
	r, err := pcapgo.NewReader(f)
	if err != nil {
		fmt.Printf("Error creating pcap reader: %s\n", err)
		return
	}
	for data, _, err := r.ReadPacketData(); err == nil; data, _, err = r.ReadPacketData() {
		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
		if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			ip := ipLayer.(*layers.IPv4)
			udp := udpLayer.(*layers.UDP)
			dumpFileName := fmt.Sprintf("Dump_%d.%d.%d.%d_%d.ts", ip.DstIP[0],
				ip.DstIP[1],
				ip.DstIP[2],
				ip.DstIP[3],
				udp.DstPort)
			of, ok := Destinations[dumpFileName]
			if !ok {
				fmt.Println("Creating new TS file", dumpFileName)
				Destinations[dumpFileName], _ = os.Create(dumpFileName)
				of, _ = Destinations[dumpFileName]
			}
			offset := 0
			if flagRTP {
				offset = 12
			}
			of.Write(packet.ApplicationLayer().Payload()[offset:])
		}
	}

	for _, fileHandle := range Destinations {
		fileHandle.Close()
	}
}

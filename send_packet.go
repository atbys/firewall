//+build ignore

package main

import (
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	device       string = "\\Device\\NPF_{1BE3DB0D-7151-42A4-8A16-A8C06AA612E4}"
	snapshot_len int32  = 1024
	promiscuous  bool   = false
	err          error
	timeout      time.Duration = 30 * time.Second
	handle       *pcap.Handle
	buffer       gopacket.SerializeBuffer
	options      gopacket.SerializeOptions
)

func main() {
	//rawBytes := []byte{1, 2, 3, 4, 5}
	srcMAC, err := net.ParseMAC("0A-00-27-00-00-37")
	dstMAC, err := net.ParseMAC("08-00-27-c2-b1-86")
	if err != nil {
		log.Fatal(err)
	}
	eth := layers.Ethernet{
		DstMAC:       dstMAC,
		SrcMAC:       srcMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := layers.IPv4{
		Version: 4,
		IHL:     5,
		TOS:     0,
		Length:  0,
		Id:      0,
		Flags:   0,
		TTL:     3,
		//Protocol: layers.IPProtocolTCP,
		SrcIP: net.IP{192, 168, 56, 1},
		DstIP: net.IP{10, 0, 2, 1},
	}

	// Open device
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	for c := 0; c < 3; c++ {
		for i := 1; i < 254; i++ {
			for j := 2; j < 5; j++ {
				ip.DstIP = net.IP{10, 0, byte(j), byte(i)}
				buffer = gopacket.NewSerializeBuffer()
				gopacket.SerializeLayers(buffer, options,
					&eth,
					&ip,
					//&tcpLayer,
					//gopacket.Payload(rawBytes),
				)
				outgoingPacket := buffer.Bytes()

				err = handle.WritePacketData(outgoingPacket)
				if err != nil {
					log.Fatal(err)
				}
				time.Sleep(100 * time.Millisecond)
			}
		}
	}
}

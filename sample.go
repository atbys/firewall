//+build ignore

package main

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	device string = "\\Device\\NPF_{D1FEB02D-0E79-4842-937F-F61FE5876B5E}"
	//device       string = "enp0s8"
	snapshot_len int32 = 1024
	promiscuous  bool  = false
	err          error
	timeout      time.Duration = 30 * time.Second
	handle       *pcap.Handle
	options      gopacket.SerializeOptions
)

func main() {
	// Open device
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// Process packet here
		ethLayer := packet.Layer(layers.LayerTypeEthernet)
		if ethLayer == nil {
			continue
		}
		eth := ethLayer.(*layers.Ethernet)
		eth.SrcMAC, _ = net.ParseMAC("00-00-00-00-00-00")
		eth.DstMAC, _ = net.ParseMAC("ff-ff-ff-ff-ff-ff")
		buffer := gopacket.NewSerializeBuffer()
		options := gopacket.SerializeOptions{
			ComputeChecksums: true,
			FixLengths:       true,
		}
		gopacket.SerializePacket(buffer, options, packet)
		fmt.Println(buffer.Bytes())
	}
}

package main

import (
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/google/gopacket/layers"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var (
	//device_wifi  string = "\\Device\\NPF_{D1FEB02D-0E79-4842-937F-F61FE5876B5E}"
	//device_wire  string = "\\Device\\NPF_{1BE3DB0D-7151-42A4-8A16-A8C06AA612E4}"
	device_wifi  string = "enp0s9"
	device_wire  string = "enp0s10"
	snapshot_len int32  = 1024
	promiscuous  bool   = true
	err          error
	timeout      time.Duration = 30 * time.Second
	handle_wifi  *pcap.Handle
	handle_wire  *pcap.Handle

	closeList map[string]bool
)

func handleConnection(conn *net.TCPConn) {
	defer conn.Close()

	buf := make([]byte, 4*1024)

	for {
		n, err := conn.Read(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok {
				switch {
				case ne.Temporary():
					continue
				}
			}
			log.Println("Read", err)
			return
		}

		slice := strings.Split(string(buf[:n]), " ")
		if len(slice) != 2 {
			conn.Write([]byte("ERROR"))
			continue
		}
		command := slice[0]
		addr := slice[1]

		out := ""
		if command == "close" {
			closeList[strings.TrimSpace(addr)] = true
			out = fmt.Sprintf("Closed: %s", addr)

		} else if command == "open" {
			_, ok := closeList[strings.TrimSpace(addr)]
			if ok {
				delete(closeList, strings.TrimSpace(addr))
				out = fmt.Sprintf("Opened: %s", addr)
			}

		} else {
			_, _ = conn.Write([]byte("ERROR"))
		}
		_, err = conn.Write([]byte(out))
		if err != nil {
			log.Println("Write", err)
			return
		}
	}
}

func handleListener(l *net.TCPListener) error {
	defer l.Close()
	for {
		conn, err := l.AcceptTCP()
		if err != nil {
			if ne, ok := err.(net.Error); ok {
				if ne.Temporary() {
					log.Println("AcceptTCP", err)
					continue
				}
			}
			return err
		}

		go handleConnection(conn)
	}
}

func main() {
	closeList = make(map[string]bool, 1024)
	closeList["8.8.8.8"] = true
	go func() {
		// Open device
		handle_wifi, err = pcap.OpenLive(device_wifi, snapshot_len, promiscuous, timeout)
		if err != nil {
			log.Fatal(err)
		}
		defer handle_wifi.Close()
		handle_wire, err = pcap.OpenLive(device_wire, snapshot_len, promiscuous, timeout)
		if err != nil {
			log.Fatal(err)
		}
		defer handle_wire.Close()

		// Use the handle as a packet source to process all packets
		packetSource := gopacket.NewPacketSource(handle_wifi, handle_wifi.LinkType())
		for packet := range packetSource.Packets() {
			// Process packet here
			// fmt.Println(packet)
			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			if ipLayer == nil {
				continue
			}
			ip := ipLayer.(*layers.IPv4)
			dstIP := ip.DstIP.String()
			if _, ok := closeList[dstIP]; ok {
				continue
			}

			ethLayer := packet.Layer(layers.LayerTypeEthernet)
			if ethLayer == nil {
				continue
			}
			eth := ethLayer.(*layers.Ethernet)
			eth.SrcMAC, err = net.ParseMAC("08-00-27-c2-b1-86")
			if err != nil {
				continue
			}
			eth.DstMAC, err = net.ParseMAC("00-00-00-00-00-00") //router's MAC
			if err != nil {
				continue
			}

			buffer := gopacket.NewSerializeBuffer()
			options := gopacket.SerializeOptions{
				ComputeChecksums: true,
				FixLengths:       true,
			}
			gopacket.SerializeLayers(buffer, options,
				eth,
				ip,
			)
			handle_wire.WritePacketData(buffer.Bytes())
			fmt.Println(buffer.Bytes())
		}
	}()
	tcpAddr, err := net.ResolveTCPAddr("tcp", "192.168.56.101:12345")
	if err != nil {
		log.Println("ResolveTCPAddr", err)
		return
	}

	l, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		log.Println("ListenTCP", err)
		return
	}

	err = handleListener(l)
	if err != nil {
		log.Println("handleListener", err)
	}
}

//+build ignore

package main

import (
	"fmt"
	"log"
	"net"
)

func main() {
	conn, err := net.Dial("tcp", "192.168.56.101:12345")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	conn.Write([]byte("close 8.8.8.9\n"))
	res := make([]byte, 4*1024)
	n, _ := conn.Read(res)
	if n == 0 {
		fmt.Println("not receive")
	}
	fmt.Println(string(res[:n]))
}

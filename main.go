package main

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type Traffic struct {
	Type  string      `json:"type"`
	Nodes interface{} `json:"nodes"`
	Links interface{} `json:"links"`
}

type Hosts struct {
	Id string `json:"id"`
}

type Connections struct {
	Source string `json:"source"`
	Target string `json:"target"`
}

// vars for gopacket
var (
	device      string = "eth0"
	snapshotLen int32  = 1024
	promiscuous bool   = false
	err         error
	timeout     time.Duration = 30 * time.Second
	handle      *pcap.Handle
)

func main() {
	// Open file instead of device
	handle, err = pcap.OpenOffline("test1.pcap")
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	ipList := []string{}
	connections := []*Connections{}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)
			ipList = getIPList(ip, ipList)
			c := createConnections(ip, connections)
			if c != nil {
				connections = c
			}
		}
	}
	uniqueIPs := getUniqueIps(ipList)
	hosts := createHosts(uniqueIPs)

	traffic := []*Traffic{}
	t := new(Traffic)
	t.Type = "web2.0"
	t.Nodes = hosts
	t.Links = connections
	traffic = append(traffic, t)
	consB, _ := json.Marshal(traffic)
	fmt.Println(string(consB))
}

// This function will take our packets and pull out all the IP Connections
// and create the struct with them.
func createConnections(ip *layers.IPv4, connections []*Connections) []*Connections {
	c := new(Connections)
	c.Source = ip.SrcIP.String()
	c.Target = ip.DstIP.String()
	connections = append(connections, c)
	return connections
}

func createHosts(uniqueIPs []string) []*Hosts {
	hosts := []*Hosts{}
	for _, ip := range uniqueIPs {
		h := new(Hosts)
		h.Id = ip
		hosts = append(hosts, h)
	}
	return hosts
}

// This function will go through the pcap and pull out unique IP addresses
func getIPList(ip *layers.IPv4, ipList []string) []string {
	ipList = append(ipList, ip.SrcIP.String(), ip.DstIP.String())
	return ipList

}

// Take in the list of IP addresses and return a list of unique ones
func getUniqueIps(ipList []string) []string {
	uniqueIPs := map[string]bool{}
	result := []string{}
	for _, v := range ipList {
		if uniqueIPs[v] == true {
			// Do not add duplicate.
		} else {
			uniqueIPs[v] = true
			result = append(result, v)
		}
	}
	return result
}

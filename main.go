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

var (
	device      string = "eth0"
	snapshotLen int32  = 1024
	promiscuous bool   = false
	err         error
	timeout     time.Duration = 30 * time.Second
	handle      *pcap.Handle
)

func main() {
	// Open device
	// Open file instead of device
	handle, err = pcap.OpenOffline("test1.pcap")
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	/* get a list of all IP addresses in the pcap */
	ipList := []string{}
	traffic := []*Traffic{}
	hosts := []*Hosts{}
	connections := []*Connections{}
	for packet := range packetSource.Packets() {
		c := printPackets(packet, connections)
		if c != nil {
			connections = c
		}
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)
			ipList = append(ipList, ip.SrcIP.String(), ip.DstIP.String())
		}
	}

	/* get all the unique IP addresses from the previous made list */
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

	for ip := range uniqueIPs {
		h := createHost(ip, hosts)
		if h != nil {
			hosts = h
		}
	}

	t := new(Traffic)
	t.Type = "web2.0"
	t.Nodes = hosts
	t.Links = connections
	traffic = append(traffic, t)
	consB, _ := json.Marshal(traffic)
	fmt.Println(string(consB))
}

func createHost(ip string, hosts []*Hosts) []*Hosts {
	h := new(Hosts)
	h.Id = ip
	hosts = append(hosts, h)

	return hosts
}

func printPackets(packet gopacket.Packet, connections []*Connections) []*Connections {
	// Let's see if the packet is IP (even though the ether type told us)
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		//fmt.Println("IPv4 layer detected.")
		ip, _ := ipLayer.(*layers.IPv4)

		// add the connections between IPs to a list
		//connections := []*Connections{}
		c := new(Connections)
		c.Source = ip.SrcIP.String()
		c.Target = ip.DstIP.String()
		connections = append(connections, c)

		return connections
	}

	return nil
}

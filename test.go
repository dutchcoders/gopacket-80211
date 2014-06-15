/**!
 * The MIT License
 *
 * Copyright (c) 2014 Remco Verhoef (github.com/dutchcoders/gopacket-80211)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * gopacket-80211
 * http://github.com/dutchcoders/gopacket-80211
 *
 * @authors http://github.com/dutchcoders/gopacket-80211/graphs/contributors
*/
package main

import (
	_ "bytes"
	_ "encoding/binary"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
        _ "hash/crc32"
	"code.google.com/p/gopacket"
	_ "code.google.com/p/gopacket/layers"
	"code.google.com/p/gopacket/pcap"
)

// scan scans an individual interface's local network for machines using ARP requests/replies.
func scan(iface *net.Interface) error {
	// We just look for IPv4 addresses, so try to find if the interface has one.
	var addr *net.IPNet
	if addrs, err := iface.Addrs(); err != nil {
		return err
	} else {
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				if ip4 := ipnet.IP.To4(); ip4 != nil {
					addr = &net.IPNet{
						IP:   ip4,
						Mask: ipnet.Mask[len(ipnet.Mask)-4:],
					}
					break
				}
			}
		}
	}
	// Sanity-check that the interface has a good address.
	if (iface.Name != "en0") {
		return nil
	}

	/*
	if addr == nil {
		return fmt.Errorf("no good IP network found")
	} else if addr.IP[0] == 127 {
		return fmt.Errorf("skipping localhost")
	} else if addr.Mask[0] != 0xff || addr.Mask[1] != 0xff {
		return fmt.Errorf("mask means network is too large")
	}
	*/
	log.Printf("using address %v for interface %v", addr, iface.Name)

	// Open up a pcap handle for packet reads/writes.
	/*
	handle, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		return err
	}
	defer handle.Close()
	*/
	handle, err := pcap.OpenOffline("/tmp/test3.pcap")
	if err != nil {
		return err
	}
	defer handle.Close()
	// Start up a goroutine to read in packet data.
	go readARP(handle, iface)
	// We don't know exactly how long it'll take for packets to be
	// sent back to us, but 10 seconds should be more than enough
	// time ;)
	time.Sleep(1000 * time.Second)
	return nil
}

func readARP(handle *pcap.Handle, iface *net.Interface) {
	fmt.Printf("readARP")
	// src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	// register MyLaer to decoder
	src := gopacket.NewPacketSource(handle, LayerTypeRadioTap) // handle.LinkType())
	for packet := range src.Packets() {
		fmt.Printf("%v", packet)
	}
}

func main() {
	// Get a list of all interfaces.
	ifaces, err := net.Interfaces()
	if err != nil {
		panic(err)
	}

	var wg sync.WaitGroup
	for _, iface := range ifaces {
		wg.Add(1)
		// Start up a scan on each interface.
		go func(iface net.Interface) {
			defer wg.Done()
			if err := scan(&iface); err != nil {
				log.Printf("interface %v: %v", iface.Name, err)
			}
		}(iface)
	}
	// Wait for all interfaces' scans to complete.
	wg.Wait()
}

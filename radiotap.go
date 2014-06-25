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
	"encoding/binary"
	"fmt"
	_ "hash/crc32"

	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
)

func align(offset uint, width uint) uint {
	return ((((offset) + ((width) - 1)) & (^((width) - 1))) - offset)
}

// Create a layer type, should be unique and high, so it doesn't conflict,
// giving it a name and a decoder to use.
var LayerTypeRadioTap = gopacket.RegisterLayerType(127, gopacket.LayerTypeMetadata{"LayerTypeRadioTap", gopacket.DecodeFunc(decodeRadioTap)})

// Implement my layer
type RadioTap struct {
	layers.BaseLayer

	// Version 0. Only increases for drastic changes, introduction of compatible new fields does not count.
	Version uint8

	// length of the whole header in bytes, including it_version, it_pad, it_len, and data fields.
	Length uint16

	// A bitmap telling which fields are present. Set bit 31 (0x80000000) to extend the bitmap by another 32 bits. Additional extensions are made by setting bit 31.
	Present uint32

	Tsft            uint64
	Flags           uint8
	ChannelTx       uint16
	ChannelRx       uint16
	ChannelFlags    uint8
	Rate            uint8
	Fhss            uint16
	DbmSignal       int8
	DbmNoise        int8
	LockQuality     uint16
	TxAttenuation   uint16
	DbTxAttenuation uint16
	Power           int8
	Antenna         uint8
	DbSignal        uint8
	DbNoise         uint8
}

const (
	IEEE80211_RADIOTAP_TSFT              uint = 0
	IEEE80211_RADIOTAP_FLAGS             uint = 1
	IEEE80211_RADIOTAP_RATE              uint = 2
	IEEE80211_RADIOTAP_CHANNEL           uint = 3
	IEEE80211_RADIOTAP_FHSS              uint = 4
	IEEE80211_RADIOTAP_DBM_ANTSIGNAL     uint = 5
	IEEE80211_RADIOTAP_DBM_ANTNOISE      uint = 6
	IEEE80211_RADIOTAP_LOCK_QUALITY      uint = 7
	IEEE80211_RADIOTAP_TX_ATTENUATION    uint = 8
	IEEE80211_RADIOTAP_DB_TX_ATTENUATION uint = 9
	IEEE80211_RADIOTAP_DBM_TX_POWER      uint = 10
	IEEE80211_RADIOTAP_ANTENNA           uint = 11
	IEEE80211_RADIOTAP_DB_ANTSIGNAL      uint = 12
	IEEE80211_RADIOTAP_DB_ANTNOISE       uint = 13
	IEEE80211_RADIOTAP_EXT               uint = 31
)
const (
	/* Channel flags. */
	IEEE80211_CHAN_TURBO   uint = 0x0010 /* Turbo channel */
	IEEE80211_CHAN_CCK     uint = 0x0020 /* CCK channel */
	IEEE80211_CHAN_OFDM    uint = 0x0040 /* OFDM channel */
	IEEE80211_CHAN_2GHZ    uint = 0x0080 /* 2 GHz spectrum channel. */
	IEEE80211_CHAN_5GHZ    uint = 0x0100 /* 5 GHz spectrum channel */
	IEEE80211_CHAN_PASSIVE uint = 0x0200 /* Only passive scan allowed */
	IEEE80211_CHAN_DYN     uint = 0x0400 /* Dynamic CCK-OFDM channel */
	IEEE80211_CHAN_GFSK    uint = 0x0800 /* GFSK channel (FHSS PHY) */
)

const (
	/* For IEEE80211_RADIOTAP_FLAGS */
	IEEE80211_RADIOTAP_F_CFP uint8 = 0x01 /* sent/received
	 * during CFP
	 */
	IEEE80211_RADIOTAP_F_SHORTPRE uint8 = 0x02 /* sent/received
	 * with short
	 * preamble
	 */
	IEEE80211_RADIOTAP_F_WEP uint8 = 0x04 /* sent/received
	 * with WEP encryption
	 */
	IEEE80211_RADIOTAP_F_FRAG uint8 = 0x08 /* sent/received
	 * with fragmentation
	 */
	IEEE80211_RADIOTAP_F_FCS     uint8 = 0x10 /* frame includes FCS */
	IEEE80211_RADIOTAP_F_DATAPAD uint8 = 0x20 /* frame has padding between
	 * 802.11 header and payload
	 * (to 32-bit boundary)
	 */
	IEEE80211_RADIOTAP_F_BADFCS  uint8 = 0x40 /* does not pass FCS check */
	IEEE80211_RADIOTAP_F_SHORTGI uint8 = 0x80 /* HT short GI */
)

func decodeRadioTap(data []byte, p gopacket.PacketBuilder) error {
	d := &RadioTap{}
	return decodingLayerDecoder(d, data, p)
}

func (m RadioTap) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return nil
}
func (m *RadioTap) LayerType() gopacket.LayerType { return LayerTypeRadioTap }

func (m *RadioTap) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	m.Version = (uint8)(data[0])
	m.Length = binary.LittleEndian.Uint16(data[2:4])
	m.Present = binary.LittleEndian.Uint32(data[4:8])
	if (m.Present & 0x80000000) == 0x80000000 {
		// offsef = offset + 1
	}

	offset := uint(8)

	if (m.Present & (1 << IEEE80211_RADIOTAP_TSFT)) > 0 {
		offset += align(offset, 8)
		m.Tsft = binary.LittleEndian.Uint64(data[offset : offset+8])
		offset += 8
	}

	if (m.Present & (1 << IEEE80211_RADIOTAP_FLAGS)) > 0 {
		m.Flags = (uint8)(data[offset])
		offset++
	}

	if (m.Present & (1 << IEEE80211_RADIOTAP_RATE)) > 0 {
		m.Rate = (uint8)(data[offset])
		offset++
	}

	if (m.Present & (1 << IEEE80211_RADIOTAP_CHANNEL)) > 0 {
		offset += align(offset, 2)
		m.ChannelTx = binary.LittleEndian.Uint16(data[offset : offset+2])
		offset += 2
		m.ChannelFlags = (uint8)(data[offset])
		offset++
	}

	if (m.Present & (1 << IEEE80211_RADIOTAP_DBM_ANTSIGNAL)) > 0 {
		m.DbmSignal = (int8)(data[offset])
		offset++
	}

	if (m.Present & (1 << IEEE80211_RADIOTAP_DBM_ANTNOISE)) > 0 {
		m.DbmNoise = (int8)(data[offset])
		offset++
	}

	if (m.Present & (1 << IEEE80211_RADIOTAP_LOCK_QUALITY)) > 0 {
		offset += align(offset, 2)
		m.LockQuality = binary.LittleEndian.Uint16(data[offset : offset+2])
		offset += 2
	}

	if (m.Present & (1 << IEEE80211_RADIOTAP_TX_ATTENUATION)) > 0 {
		offset += align(offset, 2)
		m.TxAttenuation = binary.LittleEndian.Uint16(data[offset : offset+2])
		offset += 2
	}

	if (m.Present & (1 << IEEE80211_RADIOTAP_DB_TX_ATTENUATION)) > 0 {
		offset += align(offset, 2)
		m.DbTxAttenuation = binary.LittleEndian.Uint16(data[offset : offset+2])
		offset += 2
	}

	if (m.Present & (1 << IEEE80211_RADIOTAP_DBM_TX_POWER)) > 0 {
		m.Power = (int8)(data[offset])
		offset++
	}

	if (m.Present & (1 << IEEE80211_RADIOTAP_ANTENNA)) > 0 {
		m.Antenna = (uint8)(data[offset])
		offset++
	}

	if (m.Present & (1 << IEEE80211_RADIOTAP_DB_ANTSIGNAL)) > 0 {
		m.DbSignal = (uint8)(data[offset])
		offset++
	}

	if (m.Present & (1 << IEEE80211_RADIOTAP_DB_ANTNOISE)) > 0 {
		m.DbNoise = (uint8)(data[offset])
		offset++
	}

	if (m.Present & (1 << IEEE80211_RADIOTAP_EXT)) > 0 {
		offset += align(offset, 4)
		_ = data[offset : offset+4]
		fmt.Println("Contains EXT")
		offset += 4
	}

	// if present contains ext, parse extra header

	/*
		d.Priority = (data[0] & 0xE0) >> 13
		d.DropEligible = data[0]&0x10 != 0
		d.VLANIdentifier = binary.BigEndian.Uint16(data[:2]) & 0x0FFF
		d.Type = EthernetType(binary.BigEndian.Uint16(data[2:4]))
	*/

	if (m.Flags & IEEE80211_RADIOTAP_F_DATAPAD) > 0 {
		fmt.Printf("Datapad\n")
	}

	// fmt.Printf("%v %v %v %v",8+m.Length, offset, string(data[:(8+m.Length)]), string(data[(8+m.Length):]))
	m.BaseLayer = layers.BaseLayer{Contents: data[:(m.Length)], Payload: data[(m.Length):]}
	return nil
}

func (m *RadioTap) CanDecode() gopacket.LayerClass    { return LayerTypeRadioTap }
func (m *RadioTap) NextLayerType() gopacket.LayerType { return LayerTypeDot11 }

func (m *RadioTap) String() string {
	text := fmt.Sprintf("Radiotap ")
	text += fmt.Sprintf("%v tsft ", m.Tsft)
	text += fmt.Sprintf("%v Mb/s ", 0.5*float32(m.Rate))
	text += fmt.Sprintf("%v MHz ", m.ChannelTx)
	text += fmt.Sprintf("%vdB ", m.DbmNoise)
	return text
}

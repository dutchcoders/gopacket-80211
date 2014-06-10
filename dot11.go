package main

import (
	_ "bytes"
	"encoding/binary"
	"net"
        "hash/crc32"
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
)

type layerDecodingLayer interface {
	gopacket.Layer
	DecodeFromBytes([]byte, gopacket.DecodeFeedback) error
	NextLayerType() gopacket.LayerType
}

const (
    MGT_FRAME            uint8=0x00  /* Frame type is management */
    CONTROL_FRAME        uint8=0x01  /* Frame type is control */
    DATA_FRAME           uint8=0x02  /* Frame type is Data */
    RESERVED_FRAME       uint8=0x03  /* Frame type is Reserved */
)

const (
    MGT_ASSOC_REQ          uint8=0x00  /* association request        */
    MGT_ASSOC_RESP         uint8=0x01  /* association response       */
    MGT_REASSOC_REQ        uint8=0x02  /* reassociation request      */
    MGT_REASSOC_RESP       uint8=0x03  /* reassociation response     */
    MGT_PROBE_REQ          uint8=0x04  /* Probe request              */
    MGT_PROBE_RESP         uint8=0x05  /* Probe response             */
    MGT_MEASUREMENT_PILOT  uint8=0x06  /* Measurement Pilot          */
    MGT_BEACON             uint8=0x08  /* Beacon frame               */
    MGT_ATIM               uint8=0x09  /* ATIM                       */
    MGT_DISASS             uint8=0x0A  /* Disassociation             */
    MGT_AUTHENTICATION     uint8=0x0B  /* Authentication             */
    MGT_DEAUTHENTICATION   uint8=0x0C  /* Deauthentication           */
    MGT_ACTION             uint8=0x0D  /* Action                     */
    MGT_ACTION_NO_ACK      uint8=0x0E  /* Action No Ack              */
    MGT_ARUBA_WLAN         uint8=0x0F  /* Aruba WLAN Specific        */

    CTRL_CONTROL_WRAPPER uint8=0x07  /* Control Wrapper        */
    CTRL_BLOCK_ACK_REQ   uint8=0x08  /* Block ack Request        */
    CTRL_BLOCK_ACK       uint8=0x09  /* Block ack          */
    CTRL_PS_POLL         uint8=0x0A  /* power-save poll               */
    CTRL_RTS             uint8=0x0B  /* request to send               */
    CTRL_CTS             uint8=0x0C  /* clear to send                 */
    CTRL_ACKNOWLEDGEMENT uint8=0x0D  /* acknowledgement               */
    CTRL_CFP_END         uint8=0x0E  /* contention-free period end    */
    CTRL_CFP_ENDACK      uint8=0x0F  /* contention-free period end/ack */

    DATA                        uint8=0x00  /* Data                       */
    DATA_CF_ACK                 uint8=0x01  /* Data + CF-Ack              */
    DATA_CF_POLL                uint8=0x02  /* Data + CF-Poll             */
    DATA_CF_ACK_POLL            uint8=0x03  /* Data + CF-Ack + CF-Poll    */
    DATA_NULL_FUNCTION          uint8=0x04  /* Null function (no data)    */
    DATA_CF_ACK_NOD             uint8=0x05  /* CF-Ack (no data)           */
    DATA_CF_POLL_NOD            uint8=0x06  /* CF-Poll (No data)          */
    DATA_CF_ACK_POLL_NOD        uint8=0x07  /* CF-Ack + CF-Poll (no data) */
    DATA_QOS_DATA               uint8=0x08  /* QoS Data                   */
    DATA_QOS_DATA_CF_ACK        uint8=0x09  /* QoS Data + CF-Ack        */
    DATA_QOS_DATA_CF_POLL       uint8=0x0A  /* QoS Data + CF-Poll      */
    DATA_QOS_DATA_CF_ACK_POLL   uint8=0x0B  /* QoS Data + CF-Ack + CF-Poll    */
    DATA_QOS_NULL               uint8=0x0C  /* QoS Null        */
    DATA_QOS_CF_POLL_NOD        uint8=0x0E  /* QoS CF-Poll (No Data)      */
    DATA_QOS_CF_ACK_POLL_NOD    uint8=0x0F  /* QoS CF-Ack + CF-Poll (No Data) */
)

func (m *Dot11) LayerType() gopacket.LayerType { return LayerTypeDot11 }

func decodingLayerDecoder(d layerDecodingLayer, data []byte, p gopacket.PacketBuilder) error {
	err := d.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	p.AddLayer(d)
	next := d.NextLayerType()
	if next == gopacket.LayerTypeZero {
		return nil
	}
	return p.NextDecoder(next)
}

var LayerTypeDot11 = gopacket.RegisterLayerType(105, gopacket.LayerTypeMetadata{"LayerTypeDot11", gopacket.DecodeFunc(decodeDot11)})

type Dot11 struct {
	layers.BaseLayer
        Subtype uint8
        Type uint8
        Proto uint8
        ToDS bool
        FromDS bool
        MF bool
        Retry bool
        PowerManagement bool
        MD bool
        Wep bool
        Order bool
        DurationId uint16
        // DurationId []byte
        DestinationAddress net.HardwareAddr
        SourceAddress net.HardwareAddr
        ReceiverAddress net.HardwareAddr
        TransmitterAddress net.HardwareAddr
}

func decodeDot11(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11) CanDecode() gopacket.LayerClass { return LayerTypeDot11 }

func (m *Dot11) NextLayerType() gopacket.LayerType {
        switch(m.Type) {
            case MGT_FRAME: {
                // same header for all management frames, 24 bytes
                switch (m.Subtype) {
                    case MGT_ASSOC_REQ: {
                        return LayerTypeDot11AssocReq
                    }
                    case MGT_ASSOC_RESP: {
                        return LayerTypeDot11AssocResp
                    }
                    case MGT_REASSOC_REQ: {
                        return LayerTypeDot11ReassocReq
                    }
                    case MGT_REASSOC_RESP: {
                        return LayerTypeDot11ReassocResp
                    }
                    case MGT_PROBE_REQ: {
                        return LayerTypeDot11ProbeReq
                    }
                    case MGT_PROBE_RESP: {
                        return LayerTypeDot11ProbeResp
                    }
                    case MGT_MEASUREMENT_PILOT: {
                        return LayerTypeDot11MeasurementPilot
                    }
                    case MGT_BEACON: {
                        return LayerTypeDot11Beacon
                    }
                    case MGT_ATIM: {
                        return LayerTypeDot11ATIM
                    }
                    case MGT_DISASS: {
                        return LayerTypeDot11Disassociation
                    }
                    case MGT_AUTHENTICATION: {
                        return LayerTypeDot11Authentication
                    }
                    case MGT_DEAUTHENTICATION: {
                        return LayerTypeDot11Deauthentication
                    }
                    case MGT_ACTION: {
                        return LayerTypeDot11Action
                    }
                    case MGT_ACTION_NO_ACK: {
                        return LayerTypeDot11ActionNoAck
                    }
                    case MGT_ARUBA_WLAN: {
                        return LayerTypeDot11ArubaWlan
                    }
                }
            }
            case CONTROL_FRAME: {
                switch (m.Subtype) {
                    case CTRL_CTS: {
                        return LayerTypeDot11ControlClearToSend
                    }
                }
                return LayerTypeDot11ControlFrame
            }
            case DATA_FRAME: {
                return LayerTypeDot11DataFrame
            }
        }

        // not implemented yet
	return gopacket.LayerTypePayload}

func (m *Dot11) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    m.Subtype = ((uint8)(data[0]) & 0xF0) >> 4
    m.Type = ((uint8)(data[0]) & 0x000C) >> 2
    m.Proto = ((uint8)(data[0]) & 0x0003)
    m.ToDS = (((uint8)(data[1]) & 0x01)  == 0x01)
    m.FromDS = (((uint8)(data[1]) & 0x02) == 0x02)
    m.MF = (((uint8)(data[1]) & 0x04)  == 0x04)
    m.Retry = (((uint8)(data[1]) & 0x08) == 0x08)
    m.PowerManagement = (((uint8)(data[1]) & 0x10)  == 0x10)
    m.MD = (((uint8)(data[1]) & 0x20) == 0x20)
    m.Wep = (((uint8)(data[1]) & 0x40)  == 0x40)
    m.Order = (((uint8)(data[1]) & 0x80) == 0x80)
    // fmt.Printf("Duration %v",  len(data))
    m.DurationId=binary.LittleEndian.Uint16(data[2:4])
    // m.DurationId=data[2:3]
    m.DestinationAddress=net.HardwareAddr(data[4:10])

    offset := 10

    if (m.Type == CONTROL_FRAME) {
        switch(m.Subtype) { 
            case CTRL_RTS, CTRL_PS_POLL, CTRL_CFP_END, CTRL_CFP_ENDACK: {
                m.SourceAddress=net.HardwareAddr(data[offset:offset+6])
                offset += 6
            }
        }
    } else {
        m.SourceAddress=net.HardwareAddr(data[offset:offset+6])
        offset += 6
    }

    if (m.Type == MGT_FRAME || m.Type == DATA_FRAME) {
        m.ReceiverAddress=net.HardwareAddr(data[offset:offset+6])
        offset += 6
    }

    if (m.Type != CONTROL_FRAME) {
        // Sequence
        offset +=2 
    }

    if (m.Type == DATA_FRAME && m.FromDS && m.ToDS) {
        m.TransmitterAddress=net.HardwareAddr(data[offset:offset+6])
        offset += 6
    }

    // ChecksumIEEE(data)
    // 29:31 SequenceControl

    // Frame body
    switch(m.Type) {
        case MGT_FRAME: {
            m.BaseLayer = layers.BaseLayer{Contents: data[0:offset], Payload: data[offset:len(data)-4]}
            offset = len(data)-4
        }
        case CONTROL_FRAME: {
            m.BaseLayer = layers.BaseLayer{Contents: data[0:offset], Payload: data[offset:len(data)-4]}
            offset = len(data)-4
        }
        case DATA_FRAME: {
            m.BaseLayer = layers.BaseLayer{Contents: data[0:offset], Payload: data[offset:len(data)-4]}
            offset = len(data)-4
        }
    }

    // checksum := crc32.ChecksumIEEE(data[:offset])
    _ = crc32.ChecksumIEEE(data[:offset])
    //fmt.Println("Checksum %v %v", checksum, binary.LittleEndian.Uint32(data[offset:offset+4]))
   
    // 32:36  (FCS) CRC
    /*
    checksum := crc32.ChecksumIEEE(data[0:len(data)-4])
    fmt.Println("%v %v", checksum, binary.LittleEndian.Uint32(data[len(data)-4:len(data)]))
    */
    // fmt.Printf("Destination %X Source %X", data[4:10], data[10:16])
    return (nil)
}

func (m Dot11) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return nil
}


type Dot11MgmtFrame struct {
	layers.BaseLayer
}

func (m *Dot11MgmtFrame) NextLayerType() gopacket.LayerType { return gopacket.LayerTypePayload }

var LayerTypeDot11ControlFrame = gopacket.RegisterLayerType(103001, gopacket.LayerTypeMetadata{"LayerTypeDot11ControlFrame", gopacket.DecodeFunc(decodeDot11ControlFrame)})

type Dot11ControlFrame struct {
	layers.BaseLayer
}

func (m *Dot11ControlFrame) NextLayerType() gopacket.LayerType { return gopacket.LayerTypePayload }

func (m *Dot11ControlFrame) LayerType() gopacket.LayerType { return LayerTypeDot11ControlFrame }
func (m *Dot11ControlFrame) CanDecode() gopacket.LayerClass { return LayerTypeDot11ControlFrame }
func (m *Dot11ControlFrame) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    return nil
}

func decodeDot11ControlFrame(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11ControlFrame{}
	return decodingLayerDecoder(d, data, p)
}

var LayerTypeDot11DataFrame = gopacket.RegisterLayerType(105001, gopacket.LayerTypeMetadata{"LayerTypeDot11DataFrame", gopacket.DecodeFunc(decodeDot11DataFrame)})

type Dot11DataFrame struct {
	layers.BaseLayer
}

func (m *Dot11DataFrame) NextLayerType() gopacket.LayerType { return gopacket.LayerTypePayload }

func (m *Dot11DataFrame) LayerType() gopacket.LayerType { return LayerTypeDot11DataFrame }
func (m *Dot11DataFrame) CanDecode() gopacket.LayerClass { return LayerTypeDot11DataFrame }
func (m *Dot11DataFrame) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    return nil
}

func decodeDot11DataFrame(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11DataFrame{}
	return decodingLayerDecoder(d, data, p)
}

var LayerTypeDot11InformationElement = gopacket.RegisterLayerType(102001, gopacket.LayerTypeMetadata{"LayerTypeDot11InformationElement", gopacket.DecodeFunc(decodeDot11InformationElement)})

type Dot11InformationElement struct {
	layers.BaseLayer
        Id uint8 
        Length uint8
        Oui []byte
        Info string
}

func (m *Dot11InformationElement) LayerType() gopacket.LayerType { return LayerTypeDot11InformationElement }
func (m *Dot11InformationElement) CanDecode() gopacket.LayerClass { return LayerTypeDot11InformationElement }

func (m *Dot11InformationElement) NextLayerType() gopacket.LayerType { 
    /*    
    if (false) {
        Return NIL)
    } 
    */
    return LayerTypeDot11InformationElement 
}

func (m *Dot11InformationElement) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    m.Id = data[0]
    m.Length = data[1]
    offset := uint8(1)

    if (m.Id==221) {
        m.Oui=data[offset:offset+4]
        offset += 4
    }

    m.Info = string(data[offset:offset+m.Length + 1])
    offset += m.Length + 1
    m.BaseLayer = layers.BaseLayer{Contents: data[:offset], Payload: data[offset:]}
    return nil
}

func decodeDot11InformationElement(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11InformationElement{}
	return decodingLayerDecoder(d, data, p)
}


var LayerTypeDot11ControlClearToSend = gopacket.RegisterLayerType(104001, gopacket.LayerTypeMetadata{"LayerTypeDot11ControlClearToSend", gopacket.DecodeFunc(decodeDot11ControlClearToSend)})

type Dot11ControlClearToSend struct {
	Dot11ControlFrame
}

func decodeDot11ControlClearToSend(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11ControlClearToSend{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11ControlClearToSend) LayerType() gopacket.LayerType { return LayerTypeDot11ControlClearToSend }
func (m *Dot11ControlClearToSend) CanDecode() gopacket.LayerClass { return LayerTypeDot11ControlClearToSend }
func (m *Dot11ControlClearToSend) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    return nil
}


var LayerTypeDot11AssocReq = gopacket.RegisterLayerType(1059989, gopacket.LayerTypeMetadata{"LayerTypeDot11AssocReq", gopacket.DecodeFunc(decodeDot11AssocReq)})

type Dot11AssocReq struct {
	Dot11MgmtFrame
        CapabilityInfo uint16 
        ListenInterval uint16 
        CurrentApAddress net.HardwareAddr
}

func decodeDot11AssocReq(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11AssocReq{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11AssocReq) LayerType() gopacket.LayerType { return LayerTypeDot11AssocReq }
func (m *Dot11AssocReq) CanDecode() gopacket.LayerClass { return LayerTypeDot11AssocReq }
func (m *Dot11AssocReq) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    m.CapabilityInfo=binary.LittleEndian.Uint16(data[0:2])
    m.ListenInterval=binary.LittleEndian.Uint16(data[2:4])
    m.CurrentApAddress=net.HardwareAddr(data[4:10])
    m.BaseLayer = layers.BaseLayer{Contents: data, Payload: nil}
    return nil
}

var LayerTypeDot11AssocResp = gopacket.RegisterLayerType(1059981, gopacket.LayerTypeMetadata{"LayerTypeDot11AssocResp", gopacket.DecodeFunc(decodeDot11AssocResp)})

type Dot11AssocResp struct {
	Dot11MgmtFrame
}

func decodeDot11AssocResp(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11AssocResp{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11AssocResp) CanDecode() gopacket.LayerClass { return LayerTypeDot11AssocResp }
func (m *Dot11AssocResp) LayerType() gopacket.LayerType { return LayerTypeDot11AssocResp }
func (m *Dot11AssocResp) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    m.BaseLayer = layers.BaseLayer{Contents: data, Payload: nil}
    return nil
}

var LayerTypeDot11ReassocReq = gopacket.RegisterLayerType(1059999, gopacket.LayerTypeMetadata{"LayerTypeDot11ReassocReq", gopacket.DecodeFunc(decodeDot11ReassocReq)})

type Dot11ReassocReq struct {
	Dot11MgmtFrame
        CapabilityInfo uint16
        ListenInterval uint16
        CurrentApAddress net.HardwareAddr
}

func decodeDot11ReassocReq(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11ReassocReq{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11ReassocReq) LayerType() gopacket.LayerType { return LayerTypeDot11ReassocReq }
func (m *Dot11ReassocReq) CanDecode() gopacket.LayerClass { return LayerTypeDot11ReassocReq }
func (m *Dot11ReassocReq) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    m.CapabilityInfo=binary.LittleEndian.Uint16(data[0:2])
    m.ListenInterval=binary.LittleEndian.Uint16(data[2:4])
    m.CurrentApAddress=net.HardwareAddr(data[4:10])
    m.BaseLayer = layers.BaseLayer{Contents: data, Payload: nil}
    return nil
}


var LayerTypeDot11ReassocResp = gopacket.RegisterLayerType(1059991, gopacket.LayerTypeMetadata{"LayerTypeDot11ReassocResp", gopacket.DecodeFunc(decodeDot11ReassocResp)})

type Dot11ReassocResp struct {
	Dot11MgmtFrame
}

func decodeDot11ReassocResp(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11ReassocResp{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11ReassocResp) LayerType() gopacket.LayerType { return LayerTypeDot11ReassocResp }
func (m *Dot11ReassocResp) CanDecode() gopacket.LayerClass { return LayerTypeDot11ReassocResp }
func (m *Dot11ReassocResp) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    m.BaseLayer = layers.BaseLayer{Contents: data, Payload: nil}
    return nil
}

var LayerTypeDot11ProbeReq = gopacket.RegisterLayerType(1059992, gopacket.LayerTypeMetadata{"LayerTypeDot11ProbeReq", gopacket.DecodeFunc(decodeDot11ProbeReq)})

type Dot11ProbeReq struct {
	Dot11MgmtFrame
}

func decodeDot11ProbeReq(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11ProbeReq{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11ProbeReq) LayerType() gopacket.LayerType { return LayerTypeDot11ProbeReq }
func (m *Dot11ProbeReq) CanDecode() gopacket.LayerClass { return LayerTypeDot11ProbeReq }
func (m *Dot11ProbeReq) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    m.BaseLayer = layers.BaseLayer{Contents: data, Payload: nil}
    return nil
}

var LayerTypeDot11ProbeResp = gopacket.RegisterLayerType(1059993, gopacket.LayerTypeMetadata{"LayerTypeDot11ProbeResp", gopacket.DecodeFunc(decodeDot11ProbeResp)})

type Dot11ProbeResp struct {
	Dot11MgmtFrame
}

func decodeDot11ProbeResp(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11ProbeResp{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11ProbeResp) LayerType() gopacket.LayerType { return LayerTypeDot11ProbeResp }
func (m *Dot11ProbeResp) CanDecode() gopacket.LayerClass { return LayerTypeDot11ProbeResp }
func (m *Dot11ProbeResp) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    m.BaseLayer = layers.BaseLayer{Contents: data, Payload: nil}
    return nil
}

var LayerTypeDot11MeasurementPilot = gopacket.RegisterLayerType(1059994, gopacket.LayerTypeMetadata{"LayerTypeDot11MeasurementPilot", gopacket.DecodeFunc(decodeDot11MeasurementPilot)})

type Dot11MeasurementPilot struct {
	Dot11MgmtFrame
}

func decodeDot11MeasurementPilot(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11MeasurementPilot{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11MeasurementPilot) LayerType() gopacket.LayerType { return LayerTypeDot11MeasurementPilot }
func (m *Dot11MeasurementPilot) CanDecode() gopacket.LayerClass { return LayerTypeDot11MeasurementPilot }
func (m *Dot11MeasurementPilot) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    m.BaseLayer = layers.BaseLayer{Contents: data, Payload: nil}
    return nil
}

var LayerTypeDot11Beacon = gopacket.RegisterLayerType(1059995, gopacket.LayerTypeMetadata{"LayerTypeDot11Beacon", gopacket.DecodeFunc(decodeDot11Beacon)})

type Dot11Beacon struct {
	Dot11MgmtFrame
        Timestamp uint64 
        Interval uint16
        Flags uint16
}

func decodeDot11Beacon(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11Beacon{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11Beacon) LayerType() gopacket.LayerType { return LayerTypeDot11Beacon }
func (m *Dot11Beacon) CanDecode() gopacket.LayerClass { return LayerTypeDot11Beacon }
func (m *Dot11Beacon) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    m.Timestamp=binary.LittleEndian.Uint64(data[0:8])
    m.Interval=binary.LittleEndian.Uint16(data[8:10])
    m.Flags=binary.LittleEndian.Uint16(data[10:12])
    m.BaseLayer = layers.BaseLayer{Contents: data, Payload: data[12:]}
    return nil
}

func (m *Dot11Beacon) NextLayerType() gopacket.LayerType { return LayerTypeDot11InformationElement }

var LayerTypeDot11ATIM = gopacket.RegisterLayerType(1059996, gopacket.LayerTypeMetadata{"LayerTypeDot11ATIM", gopacket.DecodeFunc(decodeDot11ATIM)})

type Dot11ATIM struct {
	Dot11MgmtFrame
}

func decodeDot11ATIM(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11ATIM{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11ATIM) LayerType() gopacket.LayerType { return LayerTypeDot11ATIM }
func (m *Dot11ATIM) CanDecode() gopacket.LayerClass { return LayerTypeDot11ATIM }
func (m *Dot11ATIM) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    m.BaseLayer = layers.BaseLayer{Contents: data, Payload: nil}
    return nil
}

var LayerTypeDot11Disassociation = gopacket.RegisterLayerType(1059997, gopacket.LayerTypeMetadata{"LayerTypeDot11Disassociation", gopacket.DecodeFunc(decodeDot11Disassociation)})

type Dot11Disassociation struct {
	Dot11MgmtFrame
}

func decodeDot11Disassociation(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11Disassociation{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11Disassociation) LayerType() gopacket.LayerType { return LayerTypeDot11Disassociation }
func (m *Dot11Disassociation) CanDecode() gopacket.LayerClass { return LayerTypeDot11Disassociation }
func (m *Dot11Disassociation) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    m.BaseLayer = layers.BaseLayer{Contents: data, Payload: nil}
    return nil
}

var LayerTypeDot11Authentication = gopacket.RegisterLayerType(1054327, gopacket.LayerTypeMetadata{"LayerTypeDot11Authentication", gopacket.DecodeFunc(decodeDot11Authentication)})

type Dot11Authentication struct {
	Dot11MgmtFrame
}

func decodeDot11Authentication(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11Authentication{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11Authentication) LayerType() gopacket.LayerType { return LayerTypeDot11Authentication }
func (m *Dot11Authentication) CanDecode() gopacket.LayerClass { return LayerTypeDot11Authentication }
func (m *Dot11Authentication) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    m.BaseLayer = layers.BaseLayer{Contents: data, Payload: nil}
    return nil
}

var LayerTypeDot11Deauthentication = gopacket.RegisterLayerType(1054328, gopacket.LayerTypeMetadata{"LayerTypeDot11Deauthentication", gopacket.DecodeFunc(decodeDot11Deauthentication)})

type Dot11Deauthentication struct {
	Dot11MgmtFrame
}

func decodeDot11Deauthentication(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11Deauthentication{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11Deauthentication) LayerType() gopacket.LayerType { return LayerTypeDot11Deauthentication }
func (m *Dot11Deauthentication) CanDecode() gopacket.LayerClass { return LayerTypeDot11Deauthentication }
func (m *Dot11Deauthentication) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    m.BaseLayer = layers.BaseLayer{Contents: data, Payload: nil}
    return nil
}

var LayerTypeDot11Action = gopacket.RegisterLayerType(1054329, gopacket.LayerTypeMetadata{"LayerTypeDot11Action", gopacket.DecodeFunc(decodeDot11Action)})

type Dot11Action struct {
	Dot11MgmtFrame
}

func decodeDot11Action(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11Action{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11Action) LayerType() gopacket.LayerType { return LayerTypeDot11Action }
func (m *Dot11Action) CanDecode() gopacket.LayerClass { return LayerTypeDot11Action }
func (m *Dot11Action) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    m.BaseLayer = layers.BaseLayer{Contents: data, Payload: nil}
    return nil
}

var LayerTypeDot11ActionNoAck = gopacket.RegisterLayerType(1054330, gopacket.LayerTypeMetadata{"LayerTypeDot11ActionNoAck", gopacket.DecodeFunc(decodeDot11ActionNoAck)})

type Dot11ActionNoAck struct {
	Dot11MgmtFrame
}

func decodeDot11ActionNoAck(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11ActionNoAck{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11ActionNoAck) LayerType() gopacket.LayerType { return LayerTypeDot11ActionNoAck }
func (m *Dot11ActionNoAck) CanDecode() gopacket.LayerClass { return LayerTypeDot11ActionNoAck }
func (m *Dot11ActionNoAck) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    m.BaseLayer = layers.BaseLayer{Contents: data, Payload: nil}
    return nil
}

var LayerTypeDot11ArubaWlan = gopacket.RegisterLayerType(1054331, gopacket.LayerTypeMetadata{"LayerTypeDot11ArubaWlan", gopacket.DecodeFunc(decodeDot11ArubaWlan)})

type Dot11ArubaWlan struct {
	Dot11MgmtFrame
}

func decodeDot11ArubaWlan(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11ArubaWlan{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11ArubaWlan) LayerType() gopacket.LayerType { return LayerTypeDot11ArubaWlan }
func (m *Dot11ArubaWlan) CanDecode() gopacket.LayerClass { return LayerTypeDot11ArubaWlan }
func (m *Dot11ArubaWlan) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    m.BaseLayer = layers.BaseLayer{Contents: data, Payload: nil}
    return nil
}
// https://code.wireshark.org/review/gitweb?p=wireshark.git;a=blob_plain;f=manuf
/*
// Now implement a decoder... this one strips off the first 4 bytes of the
// packet.
func decodeRadioTap(data []byte, p gopacket.PacketBuilder) error {
  // Create my layer
  p.AddLayer(&RadioTap{data[:8], data[8:]})
  // Determine how to handle the rest of the packet
  return p.NextDecoder(layers.LayerTypeEthernet)
}
*/


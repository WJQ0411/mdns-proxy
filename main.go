package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	mDNSAddr    = "224.0.0.251"
	mDNSPort    = 5353
	snapshotLen = int32(65535)
	promisc     = false
)

var (
	srcIface = flag.String("src-iface", "", "Source interface to receive mDNS requests")
	dstIface = flag.String("dst-iface", "", "Destination interface to forward mDNS requests")
	verbose  = flag.Bool("verbose", false, "Enable verbose logging")
)

type mDNSProxy struct {
	srcHandle *pcap.Handle
	dstHandle *pcap.Handle
	srcIP     net.IP
	dstIP     net.IP
	srcMAC    net.HardwareAddr
	dstMAC    net.HardwareAddr
	srcMTU    int
	dstMTU    int
}

func main() {
	flag.Parse()

	if *srcIface == "" || *dstIface == "" {
		log.Fatal("Both -src-iface and -dst-iface must be specified")
	}

	proxy, err := newMDNSProxy(*srcIface, *dstIface)
	if err != nil {
		log.Fatalf("Failed to create proxy: %v", err)
	}
	defer proxy.close()

	log.Printf("mDNS proxy started: %s (%s) <-> %s (%s)",
		*srcIface, proxy.srcIP, *dstIface, proxy.dstIP)

	// Handle signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)
	go func() {
		<-sigChan
		log.Println("Shutting down...")
		proxy.close()
		os.Exit(0)
	}()

	// Start forwarding
	go proxy.forward(proxy.srcHandle, proxy.dstHandle, proxy.dstIP, proxy.dstMAC, proxy.dstMTU, "src->dst")
	go proxy.forward(proxy.dstHandle, proxy.srcHandle, proxy.srcIP, proxy.srcMAC, proxy.srcMTU, "dst->src")

	// Keep main goroutine alive
	select {}
}

func newMDNSProxy(srcName, dstName string) (*mDNSProxy, error) {
	proxy := &mDNSProxy{}

	// Get source interface info
	srcNet, err := net.InterfaceByName(srcName)
	if err != nil {
		return nil, fmt.Errorf("source interface %s: %w", srcName, err)
	}
	proxy.srcIP, err = getInterfaceIPv4(srcNet)
	if err != nil {
		return nil, err
	}
	proxy.srcMAC = srcNet.HardwareAddr
	proxy.srcMTU = srcNet.MTU

	// Get destination interface info
	dstNet, err := net.InterfaceByName(dstName)
	if err != nil {
		return nil, fmt.Errorf("destination interface %s: %w", dstName, err)
	}
	proxy.dstIP, err = getInterfaceIPv4(dstNet)
	if err != nil {
		return nil, err
	}
	proxy.dstMAC = dstNet.HardwareAddr
	proxy.dstMTU = dstNet.MTU

	// Open source handle
	proxy.srcHandle, err = pcap.OpenLive(srcName, snapshotLen, promisc, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	if err := proxy.srcHandle.SetBPFFilter(fmt.Sprintf("udp port %d", mDNSPort)); err != nil {
		return nil, err
	}

	// Open destination handle
	proxy.dstHandle, err = pcap.OpenLive(dstName, snapshotLen, promisc, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	if err := proxy.dstHandle.SetBPFFilter(fmt.Sprintf("udp port %d", mDNSPort)); err != nil {
		return nil, err
	}

	return proxy, nil
}

func (p *mDNSProxy) close() {
	if p.srcHandle != nil {
		p.srcHandle.Close()
	}
	if p.dstHandle != nil {
		p.dstHandle.Close()
	}
}

func (p *mDNSProxy) forward(inHandle, outHandle *pcap.Handle, toIP net.IP, toMAC net.HardwareAddr, outMTU int, direction string) {
	log.Printf("Starting %s forwarding (out MTU: %d)", direction, outMTU)

	packetSource := gopacket.NewPacketSource(inHandle, layers.LinkTypeEthernet)
	for packet := range packetSource.Packets() {
		if err := p.processAndForward(packet, outHandle, toIP, toMAC, outMTU, direction); err != nil {
			if *verbose {
				log.Printf("[%s] Error forwarding packet: %v", direction, err)
			}
		}
	}
}

func (p *mDNSProxy) processAndForward(packet gopacket.Packet, outHandle *pcap.Handle, toIP net.IP, toMAC net.HardwareAddr, outMTU int, direction string) error {
	// Extract layers
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		return fmt.Errorf("no ethernet layer")
	}
	eth := ethLayer.(*layers.Ethernet)

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return fmt.Errorf("no IPv4 layer")
	}
	ip := ipLayer.(*layers.IPv4)

	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return fmt.Errorf("no UDP layer")
	}
	udp := udpLayer.(*layers.UDP)

	// For src->dst direction: modify A records in DNS responses
	dnsPayload := udp.Payload
	if direction == "src->dst" {
		dnsPayload = p.modifyDNSPayload(udp.Payload, toIP, direction)
	}

	// Create new packet with modified IPs
	newEth := &layers.Ethernet{
		SrcMAC:       toMAC,
		DstMAC:       eth.DstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}

	newIP := &layers.IPv4{
		Version:    4,
		IHL:        5,
		TTL:        255,
		Protocol:   layers.IPProtocolUDP,
		SrcIP:      toIP,
		DstIP:      ip.DstIP,
		Flags:      ip.Flags,
		FragOffset: ip.FragOffset,
		Id:         ip.Id,
	}

	newUDP := &layers.UDP{
		SrcPort: udp.SrcPort,
		DstPort: udp.DstPort,
	}
	newUDP.SetNetworkLayerForChecksum(newIP)

	// Serialize packet
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	err := gopacket.SerializeLayers(buf, opts,
		newEth,
		newIP,
		newUDP,
		gopacket.Payload(dnsPayload),
	)
	if err != nil {
		return err
	}

	// Check packet size against MTU
	pktBytes := buf.Bytes()
	if len(pktBytes) > outMTU+14 { // 14 bytes for Ethernet header
		if *verbose {
			log.Printf("[%s] Packet too large: %d bytes > MTU %d+14, skipping",
				direction, len(pktBytes), outMTU)
		}
		return fmt.Errorf("packet too large: %d bytes", len(pktBytes))
	}

	// Send packet
	if err := outHandle.WritePacketData(pktBytes); err != nil {
		return err
	}

	if *verbose {
		log.Printf("[%s] Forwarded %s:%d -> %s:%d (changed src to %s)",
			direction, ip.SrcIP, udp.SrcPort, ip.DstIP, udp.DstPort, toIP)
	}

	return nil
}

// DNSRecordInfo holds information about a DNS record for debugging
type DNSRecordInfo struct {
	Index    int
	NameOff  int
	Type     uint16
	TypeName string
	Class    uint16
	TTL      uint32
	RdLen    uint16
	IPOffset int // Only valid for A records
	IP       net.IP
}

// parseDNSHeader extracts DNS header information
func parseDNSHeader(payload []byte) (qr bool, numQuestions, numAnswers, numAuthorities, numAdditional uint16, err error) {
	if len(payload) < 12 {
		return false, 0, 0, 0, 0, fmt.Errorf("DNS payload too short: %d bytes", len(payload))
	}

	flags := binary.BigEndian.Uint16(payload[2:4])
	qr = flags&0x8000 != 0
	numQuestions = binary.BigEndian.Uint16(payload[4:6])
	numAnswers = binary.BigEndian.Uint16(payload[6:8])
	numAuthorities = binary.BigEndian.Uint16(payload[8:10])
	numAdditional = binary.BigEndian.Uint16(payload[10:12])

	return qr, numQuestions, numAnswers, numAuthorities, numAdditional, nil
}

// skipDNSName skips over a DNS name (handles compression pointers)
// Returns the offset after the name, or -1 on error
func skipDNSName(data []byte, offset int) int {
	if offset < 0 || offset >= len(data) {
		return -1
	}

	for offset < len(data) {
		length := int(data[offset])
		if length == 0 {
			// End of name (root label)
			return offset + 1
		}
		if length&0xC0 == 0xC0 {
			// Compression pointer (2 bytes)
			if offset+1 >= len(data) {
				return -1
			}
			return offset + 2
		}
		// Regular label: length byte + label data
		offset += length + 1
	}
	return -1
}

// parseDNSRecords parses all DNS records and returns their information
func parseDNSRecords(payload []byte) ([]DNSRecordInfo, error) {
	qr, numQuestions, numAnswers, numAuthorities, numAdditional, err := parseDNSHeader(payload)
	if err != nil {
		return nil, err
	}

	if !qr {
		return nil, nil // Not a response, nothing to modify
	}

	if *verbose {
		log.Printf("DNS: QR=%v, Questions=%d, Answers=%d, Authorities=%d, Additional=%d",
			qr, numQuestions, numAnswers, numAuthorities, numAdditional)
	}

	offset := 12 // Start after DNS header

	// Skip question section
	for i := 0; i < int(numQuestions); i++ {
		offset = skipDNSName(payload, offset)
		if offset < 0 {
			return nil, fmt.Errorf("failed to skip question %d at offset %d", i, offset)
		}
		offset += 4 // QTYPE (2) + QCLASS (2)
		if offset > len(payload) {
			return nil, fmt.Errorf("question section overflow at offset %d", offset)
		}
	}

	// Parse answer, authority, and additional sections
	var records []DNSRecordInfo
	totalRecords := int(numAnswers) + int(numAuthorities) + int(numAdditional)

	for i := 0; i < totalRecords; i++ {
		rec := DNSRecordInfo{Index: i, NameOff: offset}

		// Skip record name
		offset = skipDNSName(payload, offset)
		if offset < 0 {
			return nil, fmt.Errorf("failed to skip name for record %d at offset %d", i, offset)
		}

		// Need at least 10 bytes for TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2)
		if offset+10 > len(payload) {
			return nil, fmt.Errorf("record %d header overflow at offset %d", i, offset)
		}

		rec.Type = binary.BigEndian.Uint16(payload[offset : offset+2])
		rec.Class = binary.BigEndian.Uint16(payload[offset+2 : offset+4])
		rec.TTL = binary.BigEndian.Uint32(payload[offset+4 : offset+8])
		rec.RdLen = binary.BigEndian.Uint16(payload[offset+8 : offset+10])
		offset += 10

		// Map type number to name
		rec.TypeName = typeNameFromNumber(rec.Type)

		// For A records, record the IP offset
		if rec.Type == 1 && rec.RdLen == 4 && offset+4 <= len(payload) {
			rec.IPOffset = offset
			rec.IP = net.IP(payload[offset : offset+4])
			if *verbose {
				log.Printf("  Found A record #%d: %s at payload offset %d", i, rec.IP, offset)
			}
		}

		// Skip RDATA
		offset += int(rec.RdLen)
		if offset > len(payload) {
			return nil, fmt.Errorf("record %d RDATA overflow at offset %d", i, offset)
		}

		records = append(records, rec)
	}

	return records, nil
}

// typeNameFromNumber converts DNS record type number to human-readable name
func typeNameFromNumber(t uint16) string {
	switch t {
	case 1:
		return "A"
	case 2:
		return "NS"
	case 5:
		return "CNAME"
	case 12:
		return "PTR"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 28:
		return "AAAA"
	case 33:
		return "SRV"
	case 47:
		return "NSEC"
	default:
		return fmt.Sprintf("TYPE%d", t)
	}
}

// modifyDNSPayload modifies all A records in DNS payload to point to targetIP
// Returns the modified payload (may be a copy of original if no changes needed)
func (p *mDNSProxy) modifyDNSPayload(payload []byte, targetIP net.IP, direction string) []byte {
	targetIPv4 := targetIP.To4()
	if targetIPv4 == nil {
		if *verbose {
			log.Printf("[%s] Target IP is not IPv4: %v", direction, targetIP)
		}
		return payload
	}

	// Parse all DNS records
	records, err := parseDNSRecords(payload)
	if err != nil {
		if *verbose {
			log.Printf("[%s] Failed to parse DNS records: %v", direction, err)
		}
		return payload
	}

	// Find all A records
	var aRecordOffsets []int
	for _, rec := range records {
		if rec.Type == 1 && rec.RdLen == 4 && rec.IPOffset > 0 {
			aRecordOffsets = append(aRecordOffsets, rec.IPOffset)
		}
	}

	if len(aRecordOffsets) == 0 {
		if *verbose {
			log.Printf("[%s] No A records found to modify", direction)
		}
		return payload
	}

	// Create a copy and modify
	result := make([]byte, len(payload))
	copy(result, payload)

	for _, offset := range aRecordOffsets {
		oldIP := net.IP(result[offset : offset+4])
		if *verbose {
			log.Printf("[%s] Modifying A record at offset %d: %s -> %s",
				direction, offset, oldIP, targetIPv4)
		}
		copy(result[offset:offset+4], targetIPv4)
	}

	if *verbose {
		log.Printf("[%s] Modified %d A record(s)", direction, len(aRecordOffsets))
	}

	return result
}

func getInterfaceIPv4(iface *net.Interface) (net.IP, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}

	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
			if ip4 := ipNet.IP.To4(); ip4 != nil {
				return ip4, nil
			}
		}
	}
	return nil, fmt.Errorf("no IPv4 address found for interface %s", iface.Name)
}

package main

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	//"github.com/google/gopacket/tcpassembly"
	"fmt"
	"flag"
   "strings"
   "io"
   "errors"
   "reflect" //Allows us to read private properties
   "crypto/cipher"
   "crypto/aes"
   "crypto/rand"
   //"encoding/base64"
)

var snaplen = flag.Int("s", 16<<10, "Snaplen for pcap")
var packetCount = 0

func encrypt(data, key []byte) ([]byte, error) {
   block, err := aes.NewCipher(key)

   if err != nil {
      return nil, err
   }

   ciphertext := make([]byte, aes.BlockSize + len(data))
   iv := ciphertext[:aes.BlockSize]

   if _, err := io.ReadFull(rand.Reader, iv); err != nil {
      return nil, err
   }

   stream := cipher.NewCTR(block, iv)
   stream.XORKeyStream(ciphertext[aes.BlockSize:], data)

   return ciphertext, nil
}

func decrypt(data, key []byte) ([]byte, error) {
   block, err := aes.NewCipher(key)

   if err != nil {
      return nil, err
   }

   if len(data) < aes.BlockSize {
      return nil, errors.New("ciphertext too short")
   }

   iv := data[:aes.BlockSize]
   data = data[aes.BlockSize:]
   plaintext := make([]byte, len(data))

   stream := cipher.NewCTR(block, iv)
   stream.XORKeyStream(plaintext, data)

   return plaintext, nil
}

func handleIP(packet gopacket.Packet, ver int) {
   //fmt.Println("IP version ", ver)
   key := []byte("12345678901234567890123456789012")
   ciphertext, err := encrypt(packet.Data(), key)
   if err != nil {
      panic(err);
   }

   //fmt.Printf("\nENCRYPTED\n%0x\n", ciphertext)

   plaintext, err := decrypt(ciphertext, key)
   if err != nil {
      panic(err);
   }

   plaintext = plaintext

   //fmt.Printf("\nDECRYPTED\n%0x\n", plaintext)
}

func handleVLAN(packet gopacket.Packet) {
   //fmt.Println("VLAN")
}

func handlePacket(packet gopacket.Packet, in_handle *pcap.Handle, out_handle *pcap.Handle) {
   //printPacketInfo(packet)

   packetCount++

   ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
   if ethernetLayer != nil {
      ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
      etherType := ethernetPacket.EthernetType

      hndl_ptr := reflect.ValueOf(in_handle)
      hndl := reflect.Indirect(hndl_ptr)
      dev := hndl.FieldByName("device")

      fmt.Println(packetCount, ".", dev, ":", etherType.String())

      if etherType == layers.EthernetTypeIPv4 {
         //handleIP(packet, 4)
      } else if etherType == layers.EthernetTypeIPv6 {
         //handleIP(packet, 6)
      } else if etherType.String() == "VLAN" { // TODO: verify this ethertype with the PLC
         //handleVLAN(packet)
      } else {
         //fmt.Println("Strange ethertype: ", etherType)
      }

   }

   //retransmitPacket(packet.Data(), out_handle)
}

func retransmitPacket(data []byte, out_handle *pcap.Handle) {
   /* Write the raw packet data to the output interface */
   out_handle.WritePacketData(data)
}

func printPacketInfo(packet gopacket.Packet) {
	// Let's see if the packet is an ethernet packet
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer != nil {
      fmt.Println("Ethernet layer detected.")
      ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
      fmt.Println("Source MAC: ", ethernetPacket.SrcMAC)
      fmt.Println("Destination MAC: ", ethernetPacket.DstMAC)
      // Ethernet type is typically IPv4 but could be ARP or other
      fmt.Println("Ethernet type: ", ethernetPacket.EthernetType)
      fmt.Println()
	}

	// Let's see if the packet is IP (even though the ether type told us)
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
      fmt.Println("IPv4 layer detected.")
      ip, _ := ipLayer.(*layers.IPv4)

      // IP layer variables:
      // Version (Either 4 or 6)
      // IHL (IP Header Length in 32-bit words)
      // TOS, Length, Id, Flags, FragOffset, TTL, Protocol (TCP?),
      // Checksum, SrcIP, DstIP
      fmt.Printf("From %s to %s\n", ip.SrcIP, ip.DstIP)
      fmt.Println("Protocol: ", ip.Protocol)
      fmt.Println()
	}

	// Let's see if the packet is TCP
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		fmt.Println("TCP layer detected.")
		tcp, _ := tcpLayer.(*layers.TCP)

		// TCP layer variables:
		// SrcPort, DstPort, Seq, Ack, DataOffset, Window, Checksum, Urgent
		// Bool flags: FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS
		fmt.Printf("From port %d to %d\n", tcp.SrcPort, tcp.DstPort)
		fmt.Println("Sequence number: ", tcp.Seq)
		fmt.Println()
	}

	// Iterate over all layers, printing out each layer type
	fmt.Println("All packet layers:")
	for _, layer := range packet.Layers() {
      fmt.Println("- ", layer.LayerType())
	}

	// When iterating through packet.Layers() above,
	// if it lists Payload layer then that is the same as
	// this applicationLayer. applicationLayer contains the payload
	applicationLayer := packet.ApplicationLayer()
	if applicationLayer != nil {
      fmt.Println("Application layer/Payload found.")
      fmt.Printf("%s\n", applicationLayer.Payload())

      // Search for a string inside the payload
      if strings.Contains(string(applicationLayer.Payload()), "HTTP") {
      	fmt.Println("HTTP found!")
      }
	}

	// Check for errors
	if err := packet.ErrorLayer(); err != nil {
      fmt.Println("Error decoding some part of the packet:", err)
	}

}

func initInterfaces(plain_dev, crypto_dev string) (plain_handle, crypto_handle *pcap.Handle){
   in_handle, err := pcap.OpenLive(plain_dev, int32(*snaplen), true, pcap.BlockForever)
   if err != nil { panic(err) }
   in_handle.SetDirection(pcap.DirectionIn)
   defer in_handle.Close()

   /* Setup output device */
   out_handle, err := pcap.OpenLive(crypto_dev, int32(*snaplen), true, pcap.BlockForever)
   if err != nil { panic(err) }
   out_handle.SetDirection(pcap.DirectionIn)
   defer out_handle.Close()

   return
}

func monitorInterface(in_handle, out_handle *pcap.Handle) {
   
   /* Setup input device */
   // in_handle, err := pcap.OpenLive(in_dev, int32(*snaplen), true, pcap.BlockForever)
   // if err != nil { panic(err) }
   // in_handle.SetDirection(pcap.DirectionIn)
   // defer in_handle.Close()

   /* Setup output device */
   // out_handle, err := pcap.OpenLive(out_dev, int32(*snaplen), true, pcap.BlockForever)
   // if err != nil { panic(err) }
   // out_handle.SetDirection(pcap.DirectionIn)
   // defer out_handle.Close()

   /* Get the name of the input device */
   hndl_ptr := reflect.ValueOf(in_handle)
   hndl := reflect.Indirect(hndl_ptr)
   in_dev := hndl.FieldByName("device")

   fmt.Println("Listening on", in_dev)

   /* Create packet capture channel (infinite) */
   packetSource := gopacket.NewPacketSource(in_handle, in_handle.LinkType())
   packets := packetSource.Packets()

   for {
      select {
      case packet := <-packets:

         /* Handle the captured packet */
         handlePacket(packet, in_handle, out_handle)

      }
   }
}

func main() {
   /* Get command line arguments */
   plain_dev := flag.String("p", "eth0", "Plaintext interface")
   crypto_dev := flag.String("c", "eth1", "Encrypted interface")
	flag.Parse()

   plain_handle, crypto_handle := initInterfaces(*plain_dev, *crypto_dev)

   // Start bidirectional traffic monitoring

   //                  in device | out device | plain device
   go monitorInterface(plain_handle, crypto_handle)
   go monitorInterface(crypto_handle, plain_handle)

   /* Loop forever */
   for{}

}
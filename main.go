package main

/*
 * Run with: sudo env "PATH=$PATH" "GOPATH=$GOPATH" go run main.go
 */

import (
	"fmt"
   "strings"
   "io"
   "io/ioutil"
   "errors"
   "strconv"
   "reflect" //Allows us to read private properties

   "crypto/cipher"
   "crypto/aes"
   "crypto/rand"

   "encoding/json"

   "github.com/google/gopacket"
   "github.com/google/gopacket/layers"
   "github.com/google/gopacket/pcap"
)

var plain_iface = "eth0"
var crypto_iface = "eth1"
var key = []byte("12345678901234567890123456789012")
var encrypt_mode = "full"
var snaplen = 16<<10
var headless_mode = false

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

func handleRaw(packet gopacket.Packet, isCrypto bool) (data []byte) {
   if isCrypto {
      ciphertext, err := encrypt(packet.Data(), key)
      if err != nil { panic(err) }
      return ciphertext
   } else {
      plaintext, err := decrypt(packet.Data(), key)
      if err != nil { panic(err) }
      return plaintext
   }   
}

func handleIP(packet gopacket.Packet, ver int, isCrypto bool) (data []byte) {

   newPacket := gopacket.NewPacket(
      packet.Data(),
      layers.LayerTypeEthernet,
      gopacket.NoCopy,
   )

   ipLayer := newPacket.Layer(layers.LayerTypeIPv4)
   ip := *ipLayer.(*layers.IPv4)

   if isCrypto {
      ciphertext, err := encrypt(ip.Payload, key)
      if err != nil { panic(err) }
      ip.Payload = ciphertext
   } else {
      plaintext, err := decrypt(ip.Payload, key)
      if err != nil { panic(err) }
      ip.Payload = plaintext
   }

   return packet.Data()
}

func handleVLAN(packet gopacket.Packet) {
   
}

func handlePacket(packet gopacket.Packet, in_handle, out_handle *pcap.Handle, isCrypto bool) {

   packetCount++
   data := packet.Data()

   if encrypt_mode != "none" {

      ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
      if ethernetLayer != nil {
         ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
         etherType := ethernetPacket.EthernetType      

         if !headless_mode {
            hndl_ptr := reflect.ValueOf(in_handle)
            hndl := reflect.Indirect(hndl_ptr)
            dev := hndl.FieldByName("device")
            fmt.Println(packetCount, ":", dev, ":", etherType.String())
         }

         if encrypt_mode == "full" {

            data = handleRaw(packet, isCrypto)

         } else if encrypt_mode == "packet" {

            if etherType == layers.EthernetTypeIPv4 {
               data = handleIP(packet, 4, isCrypto)
            } else if etherType == layers.EthernetTypeIPv6 {
               //handleIP(packet, 6)
            } else if etherType.String() == "Dot1Q" { // this is VLAN (IEEE 804.1Q)
               //handleVLAN(packet)
            } else {
               //fmt.Println("Strange ethertype: ", etherType)
            }

         } // else encrypt_mode unknown

      }

   }

   retransmitPacket(data, out_handle)
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

// TODO: initialize both interfaces concurrently using goroutines
func initInterfaces(plain_dev, crypto_dev string) (plain_handle, crypto_handle *pcap.Handle, err error){
   /* Setup input device */
   plain_handle, err = pcap.OpenLive(plain_dev, int32(snaplen), true, pcap.BlockForever)
   if err != nil { panic(err) }
   plain_handle.SetDirection(pcap.DirectionIn)
   //defer in_handle.Close()

   /* Setup output device */
   crypto_handle, err = pcap.OpenLive(crypto_dev, int32(snaplen), true, pcap.BlockForever)
   if err != nil { panic(err) }
   crypto_handle.SetDirection(pcap.DirectionIn)
   //defer out_handle.Close()

   return
}

func initConfig() {

   data, err := ioutil.ReadFile("./config.json")
   if err != nil { panic(err) }

   var dat map[string]interface{}

   if err := json.Unmarshal(data, &dat); err != nil {
      panic(err)
   }

   if dat["key"] != nil {
      key = []byte(dat["key"].(string))   
   }

   if dat["plain_iface"] != nil {
      plain_iface = dat["plain_iface"].(string)   
   }

   if dat["crypto_iface"] != nil {
      crypto_iface = dat["crypto_iface"].(string)   
   }   

   if dat["encrypt_mode"] != nil {
      encrypt_mode = dat["encrypt_mode"].(string)
      if encrypt_mode != "full" || encrypt_mode != "none" || encrypt_mode != "payload" {
         panic(nil)
      }
   }

   if dat["headless_mode"] != nil {
      headless_mode, err = strconv.ParseBool(dat["headless_mode"].(string))
      if err != nil {
         panic(err)
      }
   } 
   
}

func monitorInterface(in_handle, out_handle *pcap.Handle, isCrypto bool) {

   if in_handle == nil || out_handle == nil {
      return
   }   

   if !headless_mode {
      /* Get the name of the input device */
      hndl_ptr := reflect.ValueOf(in_handle)
      hndl := reflect.Indirect(hndl_ptr)
      in_dev := hndl.FieldByName("device")

      fmt.Println("Listening on", in_dev)
   }

   /* Create packet capture channel (infinite) */
   packetSource := gopacket.NewPacketSource(in_handle, in_handle.LinkType())
   packets := packetSource.Packets()

   for {
      select {
      case packet := <-packets:

         /* Handle the captured packet */
         handlePacket(packet, in_handle, out_handle, isCrypto)

      }
   }
}

func main() {

   /* Read settings from config.json file */
   initConfig()

   /* Initialize the interfaces */
   plain_handle, crypto_handle, _ := initInterfaces(plain_iface, crypto_iface)

   /* Start bidirectional traffic monitoring */

   //                  in device | out device | is crypto
   go monitorInterface(plain_handle, crypto_handle, true)
   go monitorInterface(crypto_handle, plain_handle, false)

   /* Sleep forever */
   select{}

}
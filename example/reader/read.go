package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

type netEvent struct {
	TsNs   uint64
	PktLen uint32
	Saddr  uint32 // be32
	Daddr  uint32 // be32
	Sport  uint16 // be16
	Dport  uint16 // be16
	L4     uint8  // 6=TCP, 17=UDP
}

func main() {

	podUId := os.Getenv("POD_UID")
	pinRoot := "/sys/fs/bpf/xflow"
	extendedPinRoot := filepath.Join(pinRoot, podUId)
	pinMap := filepath.Join(extendedPinRoot, "maps")

	// spec, err := ebpf.LoadCollectionSpec("/app/bpf/ingress_filter.o")
	// if err != nil {
	// 	log.Fatalf("ebpf load error : %v", err)
	// }
	// // defer coll.Close()
	// coll, err := ebpf.NewCollection(spec)
	// if err != nil {
	// 	log.Fatalf("ebpf new collection error : %v", err)
	// }
	// rbMap, ok := coll.Maps["events"]
	// if !ok {
	// 	log.Fatalf("map 'events' not found in object")
	// }
	// defer coll.Close()
	m, err := ebpf.LoadPinnedMap(pinMap, nil)

	rd, err := ringbuf.NewReader(m)
	if err != nil {
		log.Fatalf("ringbuf reader error : %s", err)
	}
	defer rd.Close()

	log.Printf("started to listening ringbuf map")
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	go func() {
		for {
			rec, err := rd.Read()
			if err != nil {
				continue
			}

			var ev netEvent

			buf := bytes.NewReader(rec.RawSample)
			binary.Read(buf, binary.LittleEndian, &ev)

			fmt.Printf("ts=%d len=%d %s:%d -> %s:%d l4=%s\n",
				ev.TsNs, ev.PktLen,
				ipFromBE32(ev.Saddr), ntohs(ev.Sport),
				ipFromBE32(ev.Daddr), ntohs(ev.Dport),
				l4Name(ev.L4),
			)
		}

	}()
	<-sig
}
func ntohs(v uint16) uint16 { return (v<<8)&0xff00 | v>>8 }

func ipFromBE32(u uint32) net.IP {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], u)
	return net.IP(b[:])
}
func l4Name(p uint8) string {
	switch p {
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	default:
		return fmt.Sprintf("%d", p)
	}
}

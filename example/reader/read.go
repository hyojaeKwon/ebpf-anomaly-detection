package main

import (
	"bufio"
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

const sockPath = "/var/run/control-tower/daemon.sock"

func main() {
	c, err := net.Dial("unix", sockPath)
	if err != nil {
		log.Fatalf("socket connection error : %v", err)
		panic(err)
	}

	defer c.Close()
	w := bufio.NewWriter(c)

	podUId := os.Getenv("POD_UID")
	pinRoot := "/sys/fs/bpf/xflow"
	extendedPinRoot := filepath.Join(pinRoot, podUId)
	pinMap := filepath.Join(extendedPinRoot, "maps")

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

			msg := fmt.Sprintf("ts=%d len=%d %s:%d -> %s:%d l4=%s\n",
				ev.TsNs, ev.PktLen,
				ipFromBE32(ev.Saddr), ntohs(ev.Sport),
				ipFromBE32(ev.Daddr), ntohs(ev.Dport),
				l4Name(ev.L4),
			)
			w.WriteString(msg)
			w.Flush()
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

// file: user/main.go
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

/* ===== 커널 struct와 레이아웃 동일하게 맞추기 ===== */
type netEvent struct {
	TsNs   uint64
	Ifidx  uint32
	PktLen uint32
	Saddr  uint32 // be32
	Daddr  uint32 // be32
	Sport  uint16 // be16
	Dport  uint16 // be16
	Dir    uint8  // 0=in, 1=out
	L4     uint8  // 6=TCP, 17=UDP
	_      uint16 // padding
}

func ntohs(v uint16) uint16 { return (v<<8)&0xff00 | v>>8 }

func ipFromBE32(u uint32) net.IP {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], u)
	return net.IP(b[:])
}

func ifaceIndex(name string) int {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		log.Fatalf("lookup iface %q: %v", name, err)
	}
	return ifi.Index
}

/* ===== TCX attach helper (cilium/ebpf v0.19 기준) ===== */
func mustAttachTCX(prog *ebpf.Program, ifname string, attach ebpf.AttachType) link.Link {
	l, err := link.AttachTCX(link.TCXOptions{
		Interface: ifaceIndex(ifname),
		Program:   prog,
		Attach:    attach, // ebpf.AttachTCXIngress or ebpf.AttachTCXEgress
	})
	if err != nil {
		log.Fatalf("attach TCX (%v) on %s: %v", attach, ifname, err)
	}
	return l
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

func main() {
	// ---- flags ----
	iface := flag.String("iface", "eno2", "Network interface to attach (e.g., eno4, eno2, docker0)")
	obj   := flag.String("obj",   "../xflow_kern.o", "Path to BPF object file")
	flag.Parse()

	// qdisc(clsact)은 미리 설치되어 있어야 합니다:
	//   sudo tc qdisc add dev <iface> clsact || true

	// ---- load BPF object ----
	spec, err := ebpf.LoadCollectionSpec(*obj)
	if err != nil {
		log.Fatalf("LoadCollectionSpec(%s): %v", *obj, err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("NewCollection: %v", err)
	}
	defer coll.Close()

	ingProg := coll.Programs["handle_ingress"]
	egProg  := coll.Programs["handle_egress"]
	events  := coll.Maps["events"]
	if ingProg == nil || egProg == nil || events == nil {
		log.Fatalf("missing symbols: handle_ingress/handle_egress/events")
	}

	// ---- attach ingress/egress ----
	ing := mustAttachTCX(ingProg, *iface, ebpf.AttachTCXIngress)
	defer ing.Close()
	eg := mustAttachTCX(egProg, *iface, ebpf.AttachTCXEgress)
	defer eg.Close()

	// ---- ringbuf reader ----
	rd, err := ringbuf.NewReader(events)
	if err != nil {
		log.Fatalf("ringbuf.NewReader: %v", err)
	}
	defer rd.Close()

	log.Printf("listening on %s (ingress/egress). Ctrl+C to stop.", *iface)

	// ---- signal handling ----
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	// ---- event loop ----
	go func() {
		var ev netEvent
		evSize := int(unsafe.Sizeof(ev))

		for {
			rec, err := rd.Read()
			if err != nil {
				// reader가 닫히거나 일시 오류가 날 수 있음
				continue
			}
			// 길이 검증 (구조체와 다르면 스킵)
			if len(rec.RawSample) < evSize {
				log.Printf("short record: got %d bytes, need %d", len(rec.RawSample), evSize)
				continue
			}
			// RawSample → struct 복사 (패딩 포함)
			copy((*[1 << 20]byte)(unsafe.Pointer(&ev))[:evSize], rec.RawSample[:evSize])

			fmt.Printf("ts=%d if=%d len=%d %s:%d -> %s:%d dir=%s l4=%s\n",
				ev.TsNs, ev.Ifidx, ev.PktLen,
				ipFromBE32(ev.Saddr), ntohs(ev.Sport),
				ipFromBE32(ev.Daddr), ntohs(ev.Dport),
				map[uint8]string{0: "in", 1: "out"}[ev.Dir],
				l4Name(ev.L4),
			)
		}
	}()

	<-sig
	log.Println("bye")
}
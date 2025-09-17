package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func main() {

	podUId := os.Getenv("POD_UID")
	// targets
	iface := "eth0"
	obj := "/app/bpf/ingress_filter.o"

	pinRoot := "/sys/fs/bpf/xflow"
	extendedPinRoot := filepath.Join(pinRoot, podUId)
	log.Printf("%s", extendedPinRoot)
	pinProgIngress := filepath.Join(extendedPinRoot, "prog_ingress")
	pinLinkIngress := filepath.Join(extendedPinRoot, "link_ingress")
	// pinProgEgress  = "/sys/fs/bpf/xflow/prog_egress"
	// pinLinkEgress  = "/sys/fs/bpf/xflow/link_egress"

	// 2. bpffs 폴더 보장
	ensureDir(extendedPinRoot)
	// 3 eBPF 오브젝트 로딩
	spec, err := ebpf.LoadCollectionSpec(obj)
	if err != nil {
		log.Fatalf("LoadCollectionSpec: %v", err)
	}
	coll, err := ebpf.NewCollection(spec)

	log.Println("==== spec programs ====")
	for name := range spec.Programs {
		log.Printf("spec program: %s", name)
	}
	log.Println("==== loaded programs ====")
	for name := range coll.Programs {
		log.Printf("loaded program: %s", name)
	}

	// 4. 프로그램 찾기
	ingress := coll.Programs["ingress_custom_ebpf"]
	if ingress == nil {
		log.Fatalf("missing programs")
	}
	defer coll.Close()
	// 5. 프로그램 핀
	pinProgram(ingress, pinProgIngress)

	// 6. TCX 부착
	ingressLink := attachTCX(ingress, iface, ebpf.AttachTCXIngress)
	defer ingressLink.Close()

	// 7. 링크 핀
	if err := ingressLink.Pin(pinLinkIngress); err != nil {
		log.Fatalf("pin ingress link: %v", err)

	}

	log.Printf("OK: TCX ingress attached on %s and pinned at %s", iface, pinLinkIngress)
}

func attachTCX(prog *ebpf.Program, ifname string, attach ebpf.AttachType) link.Link {
	ifaceIndex, err := net.InterfaceByName(ifname)
	if err != nil {
		log.Fatalf("lookup iface %q: %v", ifname, err)
	}
	l, err := link.AttachTCX(link.TCXOptions{
		Interface: ifaceIndex.Index,
		Program:   prog,
		Attach:    attach,
		// Flags:     unix.BPF_F_REPLACE,
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

// 핀할 폴더 만들어주기
func ensureDir(p string) {
	if err := os.MkdirAll(p, 0755); err != nil && !errors.Is(err, os.ErrExist) {
		log.Fatalf("mkdir %s: %v", p, err)
	}
}

// 프로그램 핀하는건데 원래 있으면 그거 사용
func pinProgram(prog *ebpf.Program, path string) {
	if _, err := ebpf.LoadPinnedProgram(path, nil); err == nil {
		log.Printf("reusing pinned program at %s", path)
		return
	}
	if err := prog.Pin(path); err != nil {
		log.Fatalf("prog Pin(%s): %v", path, err)
	}
	log.Printf("program pinned at %s", path)
}

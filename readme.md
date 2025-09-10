# eBPF 실습

**아직 진행 중인 프로젝트이며 보완할 점이 많음. 차차 디벨롭할 예정** 

eBPF를 커널의 네트워크 경로(TC 훅)에 붙여 패킷 메타데이터를 드롭 없이 ringbuf로 전달한 후 Go 리더가 ringbuf를 읽어 콘솔에 출력하는 것을 1차 목표로 한다.

```
[네트워크 트래픽]
       │
       ▼
   (NIC / 드라이버)
       │
       ├── Ingress  ┐
       │            │  eBPF(커널 C): IPv4 + TCP/UDP만 살짝 파싱
       └── Egress   ┘
                │   (패킷은 항상 통과: Drop 안 함)
                ▼
          [BPF Ring Buffer]
                │
                ▼
       [Go 프로그램 (Reader)]
                │
                ▼
             [로그/출력]
```

드롭 없이 패킷 흐름을 관찰만 하는 구조이며, 

## 수집(목표)

- 대상: 파드 eht0(파드 측 veth) ingress/egress 트래픽
- 추출 필드: ts, saddr, daddr. sport, dport, len 5-tuple
- 부착 지점: 파드 영역 veth에 tc hook
- 커널 유저 공간 전달은 BPF ringbuf

목표 달성을 위해 세 가지 실험으로 분리하였다.

1. 호스트(노드) 이더넷 인터페이스에 ebpf prog을 부착하여 패킷이 흐를 때 마다 ebpf_printk 찍어보기
2. 호스트(노드) 이더넷 인터페이스에 ebpf prog을 부착하여 패킷 메타데이터를 ring buf로 올리고 gorutine을 통해 읽어오기
3. 쿠버네티스 파드의 veth에 ebpf prog을 부착하여 파드에 출입하는 패킷 메타데이터를 ring buf + per cpu map에 올려서 확인하기 (특정 파드에 흐르는 네트워크 흐름을 관찰하기 위함이다.)

## 전체 구조

```c
ebpf-demo/
├─ vmlinux.h         # bpftool로 생성 (아래 2단계)
├─ xflow_kern.c      # eBPF(커널) 코드
├─ Makefile          # 커널 오브젝트 빌드,
└─ user/
   └─ main.go        # 유저 공간 코드(Go)
```

## 코드레벨 description

go 같은 경우에는 처음 해보는거라 gpt의 도움을 받았다. eBPF같은 경우에는 isovalent에서 제공해주는 lab session도움을 많이 받았으며, 참고하였다.

- **vmlinux.h**
    
    `sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h`
    이 파일은 노드의 현재 커널의 타입 정의를 담고 있어서, 코드가 커널 버전에 자동으로 적응하도록 하는 CO-RE구조이다.
    
- xflow_kern.c
    
    ```c
    #include "vmlinux.h"
    #include <bpf/bpf_helpers.h>
    #include <bpf/bpf_endian.h>
    ```
    
    vmlinux: 현재 커널의 BTF 타입 정보로부터 생성된 헤더이다. co-re 방식에서 커널 구조체 레이아웃 차이를 흡수하기 위하여 사용된다. 이 헤더 파일에는 struct ethhdr, struct iphdr, struct tcphdr, struct udphdr등 커널 타입 정의가 들어있다.
    
    bpf_helpers.h: eBPF 핼퍼 함수와 SEC매크로, 맵/프로그램 정의용 특성들의 선언되어 있다.
    
    bpf_endian.h: 네트워크 바이트 오더 변환용 매크로/인라인 함수가 들어 있다. 패킷 필드는 big-endian이고 cpu는 보통 little-endian이므로 변환이 필요하다.
    
    ```c
    #define L4_TCP 6
    #define L4_UDP 17
    ```
    
    IP헤더의 protocol 필드 값과 동일하다. tcp = 6 / udp = 17
    
    ```c
    // ringbuf map
    struct {
        __uint(type, BPF_MAP_TYPE_RINGBUF);
        __uint(max_entries, 1 << 24); // 맵 크기를 16MB로 설정하는 것인데, 트래픽이 많으면 늘려야할수도 있슴
    } events SEC(".maps");
    ```
    
    커널에서 유저스페이스로 이벤트를 전달하기 위한 ringbuf map정의.
    
    libbpf 스타일의 맵 선언이다. __uint(type, …), SEC(”.maps”)는 ELF 색션에 맵 메타디이터를 박아서 유저 공간 로더가 이 맵을 생성하도록 한다.
    
    BPF_MAP_TYPE_RINGBUF: 커널 → 유저 공간의 데이터를 제로 카피에 보내는 고성능 큐이다.
    
    - max_entries는 바이트 단위 용량이다. 16MB버퍼를 할당하였다. 이벤트 레코드가 더 많을수록 크게 잡아야 유실을 방지할 수 있다.
    
    ```c
    // event payload
    struct net_event{
        __u64 ts_ns; // 타임스탬프
        __u32 ifindex; // 인터페이스 인덱스
        __u32 pkt_len;
        __u32 saddr; // IPv4 src 
        __u32 daddr; // dst
        __u16 sport;
        __u16 dport;
        __u8 dir; // 0: ingress 1: egress
        __u8 l4; // 6 tcp - 17 udp
        __u16 _pad; // 정렬을 위함
    };
    ```
    
    네트워크 패킷을 수집하기 위한 struct이다.
    
    유저 공간과 동일한 메모리 레이아웃을 갖도록 설계한 것이다. _pad는 구조체 정렬을 안정화하기 위한 필드이다. 유저 공간 struct에도 동일한 패딩을 두면 안전하다.
    
    ```c
    static __always_inline int parse_l3_l4(void *data, void *data_end, struct net_event *ev){
        struct ethhdr *eth = data;
        if((void *)(eth + 1) > data_end){
            return 0;
        } // out of bounds 접근 예방
    	
    		// IPv4인지 확인한다.
        __u16 hproto = bpf_ntohs(eth -> h_proto);
        if(hproto != ETH_P_IP){
            return 0;
        }
    ```
    
    패킷 파싱에서 가장 중요한 것인 boundary check이다.
    
    eBPF 검증기가 모든 포인터 접근이 안전한지 증명해야 통과한다.
    
    ```c
        struct iphdr *iph = (void*)(eth + 1);
        if ((void*)(iph + 1) > data_end)
            return 0;
        if (iph->version != 4)
            return 0;
    
        __u32 ihl = iph->ihl * 4;
        if (ihl < sizeof(*iph))
            return 0;
    
        void *l4hdr = (void*)iph + ihl;
        if (l4hdr > data_end)
            return 0;
    ```
    
    ipv4헤더는 가변 길이이고, ihl(4비트에 4를 곱하여 바이트 길이를 만들고 그 길이만큼 L4 헤더 시작 위치를 계산한다. 만약 계산한 헤더 길이가 최소보다 작거나 포인터가 data_end를 넘어가면 실패처리
    
    ```c
        ev->saddr = iph->saddr;
        ev->daddr = iph->daddr;
    
        if (iph->protocol == IPPROTO_TCP) {
            struct tcphdr *tcph = l4hdr;
            if ((void*)(tcph + 1) > data_end)
                return 0;
            ev->l4    = L4_TCP;
            ev->sport = tcph->source; // be16
            ev->dport = tcph->dest;   // be16
            return 1;
        } else if (iph->protocol == IPPROTO_UDP) {
            struct udphdr *udph = l4hdr;
            if ((void*)(udph + 1) > data_end)
                return 0;
            ev->l4    = L4_UDP;
            ev->sport = udph->source; // be16
            ev->dport = udph->dest;   // be16
            return 1;
        }
        return 0;
    }
    ```
    
    L4가 TCP/UDP인 경우에만 포트 필드를 읽는다. 성공하면 1을 아니면 0을 반환하여 상위 로직에서 discard.submit를 결정한다. 즉 ipv4이고 TCP/UDP이여야만 src/dst ip, src/dst port, protocol을 ev에 채워준다.
    
    ```c
    static __always_inline int handle_pkt(struct __sk_buff *skb, __u8 dir) {
        void *data     = (void *)(long)skb->data;
        void *data_end = (void *)(long)skb->data_end;
    
        struct net_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
        if (!ev)
            return BPF_OK;
    ```
    
    eBPF TC프로그램의 인자 struct __sk_buff의 *skb는 패킷 메타 정보를 담고 있다. skb→data, skb→data_end는 패킷 데이터 영역의 시작과 끝 주소다. (커널 메모리 상)
    
    ringbuf에 이벤트를 쓸 버퍼를 예약하는 구조이다.
    
    실패 시 패킷은 드롭하지 말고 그대로 BPF_OK를 반환하여 패킷은 계속 통과시킨다.
    
    ```c
        ev->ts_ns   = bpf_ktime_get_ns();
        ev->ifindex = skb->ifindex;
        ev->pkt_len = skb->len;
        ev->dir     = dir;
        ev->l4      = 0; ev->sport = 0; ev->dport = 0; ev->_pad = 0;
    
        if (!parse_l3_l4(data, data_end, ev)) {
            bpf_ringbuf_discard(ev, 0);
            return BPF_OK;
        }
    ```
    
    타임스탬프, 인터페이스 인댁스, 패킷 길이를 먼저 채우고, parse_l3_l4(위에 정의된 함수)가 실패하면 예약된 레코드를 버리고 패킷은 통과시킨다.
    
    ```c
        bpf_ringbuf_submit(ev, 0);
        return BPF_OK;
    ```
    
    이벤트를 ringbuf에 submit한다.
    
    반환값 BPF_OK는 TC 프로그램에서 TC_ACT_OK(패킷 통과)와 동일하게 해석된다.
    
    결국 이 함수는 하나의 패킷을 이벤트로 만들고 ringbuf에 올릴지 말지 결정한다. 또한, 패킷을 드롭하지 않도록 설계되어 있다.
    
    ```c
    SEC("tc")
    int handle_ingress(struct __sk_buff *skb){
        return handle_pkt(skb, 0);
    }
    
    SEC("tc")
    int handle_egress(struct __sk_buff *skb){
        return handle_pkt(skb, 1);
    }
    ```
    
    TC 훅 엔트리
    
    SEC(”tc”) 이 함수들이 TC hook 타입의 eBPF 프로그램으로 빌드되도록 ELF 섹션을 지정한다. 유저 공간에서 섹션명으로 특정 함수를 attach한다.
    
- main.go(정리 중)
    
    go 언어 사용은 아예 처음이라서 line-by-line으로 코드레벨 정리를 해 보았다
    
    ```go
    package main
    ```
    
    go는 package main + func main()이 있어야 실행 가능한 binary를 만들 수 있다.
    
    ```go
    import (
    	"encoding/binary" //바이트 정수 변환
    	"fmt" // 출력
    	"log" // 로그 출력
    	"net" // 네트워크 인터페이스 조회에 사용
    	"os" // os signal 처리 용
    	"os/signal"
    	"syscall"  
    	"unsafe" // 메모리 복사/캐스팅에 사용되는 저수준 기능이다.
    
    	"github.com/cilium/ebpf" // eBPF 오브젝트 로드/맵/프로그램 관리 go 라이브러리
    	"github.com/cilium/ebpf/link"  // 커널 hook에 프로그램을 붙일 때 사용
    	"github.com/cilium/ebpf/ringbuf" // ringbuf reader
    )
    ```
    
    사용한 패키지 목록이다.
    
    ```go
    	rd, err := ringbuf.NewReader(events)
    	if err != nil {
    		log.Fatalf("ringbuf reader: %v", err)
    	}
    	defer rd.Close()
    ```
    
    커널의 BPF_MAP_TYPE_RINGBIF 맵을 읽기 위한 reader생성 부분이고 이후에 rd.read로 이벤트를 하나씩 읽음
    
    ```go
    	go func() {
    		for {
    			rec, err := rd.Read()
    			if err != nil {
    				continue
    			}
    			var ev netEvent
    			// RawSample을 struct로 메모리 복사 (패딩 포함)
    			size := int(unsafe.Sizeof(ev))
    			copy((*[1 << 20]byte)(unsafe.Pointer(&ev))[:size], rec.RawSample)
    ```
    
    rd.Read()는 ringbuf에서 한 이벤트를 가져오는 블로킹 호출이다.
    
    rec.RawSample은 []byte로서 이벤트의 원시 바이트이다. 
    
    ev의 사이즈 만큼 복사해서 struct를 채우는 것이다.
    

## Pod veth 커널에 eBPF 붙이기

노드 이더넷 인터페이스는 유동적이지 않아, eBPF 커널을 붙이기 수월했다. (바로 위 스위치에서 untagged된 패킷이 내려온다) 그러나, 파드의 veth에 커널을 붙이기 위해서는 자동적으로 pod생성 시 eBPF를 붙이는 로직이 필요했고, 아직 그 구현체를 준비하지 않아 파드의 PID, PID를 통한 veth를 찾아서 직접 bpftool로 붙였다.

(추가로 cilium CNI사용 중인데, kernel에 붙어있는 cilium eBPF를 삭제할까봐 신중히 작업을 진행했다.)

그 과정은 다음과 같다.

1. kubectl -n ebpf-test pod description $POD_NAME 을 통해서 container ID를 가져온다.
2. crictl 을 통하여 container ID로부터 PID를 가져온다 (가상화머신으로 containerd를 사용중이다.)
3. 파드 netns안에서 호스트 인터페이스 중 파드의 eth0을 찾는다. (lxc*는 호스트 네임스페이스에 존재하는 veth 인터페이스이다. cilium이 파드 생성 시 자동으로 만드는 veth로, 컨테이너의 eth0과 페어를 이룬다.)
4. 빌드된 eBPF오브젝트를 bpftool을 이용하여 veth에 붙인다. (eBPF 오브젝트를 핀 한 후에 sudo tc filter add dev $DEV ingress pref 120 protocol all bpf da pinned /sys/fs/bpf/xflow/handle_ingress 를 통하여 부착함. egress동일) 
5. 이후 service → pod를 거쳐서 패킷이 전송되는지 확인했다.

## 결과

http-echo pod를 띄운 뒤 접속하여 파드로 흐른 데이터의 수를 체크하는 per cpu map에 count를 저장한 모습이다.

<img width="245" height="717" alt="image" src="https://github.com/user-attachments/assets/0c417e4d-36e3-4cf8-b1a1-2ea1017668e0" />


추가(보완)할 것

1. ringbuf유실이 있는지 모너티링
2. VLAN 태그 관련 정리
3. eBPF로드 자동 절차

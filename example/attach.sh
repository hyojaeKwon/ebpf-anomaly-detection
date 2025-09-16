#!/bin/sh
set -euo pipefail

# -------- 설정 --------
DEV="${DEV:-eth0}"
OBJ="${OBJ:-/app/ingress_filter.o}"   # 섹션이 반드시 "tc" 또는 "tc/ingress" 여야 함
SEC="${SEC:-tc}"
PIN="${PIN:-/sys/fs/bpf/tc_ingress}"  # 프로그램 핀 위치

log() { printf '%s %s\n' "[$(date +%H:%M:%S)]" "$*"; }

# -------- 사전 점검 --------
# bpffs / debugfs 마운트 (멱등)
mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true
mount -t debugfs none /sys/kernel/debug 2>/dev/null || true

# (CO-RE를 쓴다면) 커널 BTF 확인
if [ -f /sys/kernel/btf/vmlinux ]; then
  ls -l /sys/kernel/btf/vmlinux
else
  log "WARNING: /sys/kernel/btf/vmlinux not found (CO-RE면 필요)"
fi

# 툴 확인
command -v tc >/dev/null 2>&1 || { log "ERROR: tc not found"; exit 127; }
command -v bpftool >/dev/null 2>&1 || { log "ERROR: bpftool not found"; exit 127; }

# 오브젝트 존재
ls -l "$OBJ" || { log "ERROR: object not found: $OBJ"; exit 2; }

log "[*] dev=$DEV obj=$OBJ sec=$SEC pin=$PIN"

# -------- qdisc 준비 --------
if tc qdisc add dev "$DEV" clsact 2>/dev/null; then
  log "[+] qdisc clsact added"
else
  log "[=] qdisc already present"
fi

# -------- BPF 로드 & 핀 --------
# 기존 pin 제거(교체를 위한 멱등 처리)
rm -f "$PIN" 2>/dev/null || true

log "[*] loading & pinning with bpftool (verbose)"
# NOTE: 검증기(Verifier) 로그가 여기서 자세히 출력됨
bpftool prog load "$OBJ" "$PIN" 

# -------- tc에 링크(attach) --------
# 기존 필터 지우고 붙이기(멱등)
IFINDEX=$(cat /sys/class/net/"$DEV"/ifindex)

bpftool net attach tcx_ingress pinned "$PIN" dev eth0

# bpftool link show | grep -E "tcx_ingress|tcx_egress" || true

log "[OK] tc attach ready"
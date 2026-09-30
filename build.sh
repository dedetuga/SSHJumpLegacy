#!/usr/bin/env bash
# Build the SSH Jump classic-ACAP package (.eap) for Axis ARTPEC-4 / ARTPEC-5.
#
# ARTPEC-4 (34Kc) and ARTPEC-5 (1004Kc) are the SAME build target: MIPS32r2,
# little-endian, soft-float, o32 ABI, APPTYPE=mipsisa32r2el. The Go daemon is a
# static binary (no libc); the launcher is a tiny position-independent (ET_DYN)
# ELF that satisfies elflibcheck and exec()s the daemon. So one binary runs on
# both SoCs -- we just stamp the output name with the SoC you pass.
#
# Usage:   ./build.sh [artpec4|artpec5|both]      (default: both)
#
# Requirements on the build host:
#   - Go >= 1.24.1   (has the fix for golang/go#71591, a MIPS-softfloat hang)
#   - mipsel-linux-gnu-gcc + binutils  (Debian/Ubuntu: gcc-mipsel-linux-gnu)
#   - qemu-user-static (optional, only for ./build.sh test)
set -euo pipefail

APP=sshjump
VER_MAJOR=1; VER_MINOR=0; VER_MICRO=0
VERSION="${VER_MAJOR}.${VER_MINOR}.${VER_MICRO}"
INSTALL_DIR="/usr/local/packages/${APP}"          # where the app lives on the camera
REAL_BIN="${INSTALL_DIR}/bin/${APP}"              # the real Go daemon (launcher execs this)

ROOT="$(cd "$(dirname "$0")" && pwd)"
OUT="${ROOT}/out"
CC="${CC:-mipsel-linux-gnu-gcc}"
GO="${GO:-go}"

log(){ printf '\033[1;36m==>\033[0m %s\n' "$*"; }

# --- 1. generate + compile the PIE launcher ---------------------------------
# A freestanding MIPS32r2 stub (no libc, no relocations) that execve()s REAL_BIN,
# preserving argv/env. Built as a dynamic PIE (interp /lib/ld.so.1, no NEEDED
# libs) so it is ET_DYN -- what elflibcheck.sh demands -- yet runs on any glibc.
build_launcher(){
  log "generating launcher stub for ${REAL_BIN}"
  mkdir -p "${OUT}"
  python3 - "$REAL_BIN" > "${OUT}/launch.S" <<'PY'
import sys
p = sys.argv[1].encode() + b'\0'
while len(p) % 4: p += b'\0'
words = [int.from_bytes(p[i:i+4], 'little') for i in range(0, len(p), 4)]
alloc = ((len(p) + 15)//16)*16
L = []
L.append('\t.abicalls')
L.append('\t.set\tnoreorder')
L.append('\t.text')
L.append('\t.globl\t__start')
L.append('\t.globl\t_start')
L.append('\t.ent\t_start')
L.append('_start:')
L.append('__start:')
L.append('\tlw\t$t0, 0($sp)')          # argc
L.append('\taddiu\t$a1, $sp, 4')       # argv
L.append('\taddiu\t$t1, $t0, 1')
L.append('\tsll\t$t1, $t1, 2')
L.append('\taddu\t$a2, $a1, $t1')      # envp = argv + (argc+1)*4
L.append('\taddiu\t$sp, $sp, -%d' % alloc)
for i, w in enumerate(words):
    L.append('\tli\t$t2, 0x%08x' % w)
    L.append('\tsw\t$t2, %d($sp)' % (i*4))
L.append('\tmove\t$a0, $sp')           # path
L.append('\tli\t$v0, 4011')            # __NR_execve (o32)
L.append('\tsyscall')
L.append('\tnop')
L.append('\tli\t$a0, 1')
L.append('\tli\t$v0, 4001')            # __NR_exit
L.append('\tsyscall')
L.append('\tnop')
L.append('\t.end\t_start')
sys.stdout.write('\n'.join(L) + '\n')
PY
  log "compiling launcher with ${CC}"
  "${CC}" -march=mips32r2 -mabi=32 -EL -nostdlib -nostartfiles -pie \
    -Wl,-e,_start -o "${OUT}/${APP}" "${OUT}/launch.S"
  # sanity: must be ET_DYN with no relocations
  if command -v readelf >/dev/null; then
    readelf -h "${OUT}/${APP}" | grep -q 'DYN' || { echo "launcher is not ET_DYN!"; exit 1; }
  fi
}

# --- 2. build the Go daemon (static, mipsle softfloat) ----------------------
build_daemon(){
  log "building Go daemon (GOARCH=mipsle GOMIPS=softfloat, static)"
  mkdir -p "${OUT}/bin"
  ( cd "${ROOT}/app" && \
    GOOS=linux GOARCH=mipsle GOMIPS=softfloat CGO_ENABLED=0 GOFLAGS=-mod=vendor \
    "${GO}" build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o "${OUT}/bin/${APP}" . )
}

# --- 3. assemble the .eap (gzip tar; package.conf at root) ------------------
package(){
  local soc="$1"
  log "packaging ${APP} ${VERSION} for ${soc}"
  local stage="${OUT}/stage"
  rm -rf "${stage}"; mkdir -p "${stage}/bin" "${stage}/html"
  cp "${ROOT}/packaging/package.conf" "${ROOT}/packaging/cgi.txt" \
     "${ROOT}/packaging/param.conf"   "${ROOT}/packaging/LICENSE" \
     "${ROOT}/packaging/zz_${APP}_proxy.conf" "${ROOT}/packaging/postinstall.sh" "${stage}/"
  cp "${OUT}/${APP}"     "${stage}/${APP}"        # PIE launcher (package root)
  cp "${OUT}/bin/${APP}" "${stage}/bin/${APP}"    # real Go daemon
  cp "${ROOT}"/web/*     "${stage}/html/"
  chmod 755 "${stage}/${APP}" "${stage}/bin/${APP}"
  local eap="${OUT}/${APP}_${VER_MAJOR}_${VER_MINOR}_${VER_MICRO}_${soc}_mipsisa32r2el.eap"
  ( cd "${stage}" && tar czf "${eap}" package.conf cgi.txt param.conf LICENSE \
       "${APP}" "zz_${APP}_proxy.conf" postinstall.sh bin html )
  log "built ${eap} ($(stat -c%s "${eap}") bytes)"
}

target="${1:-both}"
build_launcher
build_daemon
case "${target}" in
  artpec4) package artpec4 ;;
  artpec5) package artpec5 ;;
  both)    package artpec4; package artpec5 ;;
  test)    package artpec5;
           command -v qemu-mipsel-static >/dev/null && {
             log "smoke test under qemu"; SOCK=$(mktemp -u)
             SSHJUMP_SOCKET="$SOCK" qemu-mipsel-static "${OUT}/bin/${APP}" & p=$!; sleep 1
             curl -s --unix-socket "$SOCK" "http://x/control.cgi?op=health"; echo
             kill $p 2>/dev/null; rm -f "$SOCK"; } ;;
  *) echo "usage: $0 [artpec4|artpec5|both|test]"; exit 1 ;;
esac
log "done. Artifacts in ${OUT}/"

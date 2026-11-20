#!/usr/bin/env bash
# install.sh — build secrethunter2 dari source repo ini lalu pasang sebagai
# FILE BIASA (bukan symlink) di $BINDIR (default /usr/local/bin).
#
#   ./install.sh                 build + pasang ke /usr/local/bin
#   BINDIR=~/.local/bin ./install.sh
#   PREFIX=/opt/tools ./install.sh    → /opt/tools/bin
#   ./install.sh --uninstall     hapus $BINDIR/secrethunter2 saja
#
# Update: git pull && ./install.sh
#
# Script ini tidak meng-install Go, tidak men-download/clone apa pun, dan tidak
# mengubah PATH maupun shell rc. Idempoten: aman dijalankan berulang.
set -euo pipefail

readonly NAME="secrethunter2"
readonly MIN_GO_MAJOR=1
readonly MIN_GO_MINOR=21 # sesuai go.mod

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIR

if [[ -n "${BINDIR:-}" ]]; then
	BIN_DIR="$BINDIR"
elif [[ -n "${PREFIX:-}" ]]; then
	BIN_DIR="${PREFIX%/}/bin"
else
	BIN_DIR="/usr/local/bin"
fi
[[ "$BIN_DIR" == "/" ]] || BIN_DIR="${BIN_DIR%/}"
readonly BIN_DIR
readonly DEST="$BIN_DIR/$NAME"

info() { printf '[*] %s\n' "$*"; }
warn() { printf '[!] WARN: %s\n' "$*" >&2; }
die() {
	printf '[x] ERROR: %s\n' "$*" >&2
	exit 1
}

usage() {
	cat <<EOF
Usage: ./install.sh [--uninstall] [-h|--help]

Build $NAME dari source di direktori script ini lalu pasang ke:
  $DEST

Opsi:
  --uninstall   hapus \$BINDIR/$NAME (hanya file itu; salinan lain tidak disentuh)
  -h, --help    tampilkan bantuan ini

Variabel lingkungan:
  BINDIR=<dir>  direktori tujuan (default /usr/local/bin)
  PREFIX=<dir>  tujuan = <dir>/bin (diabaikan bila BINDIR diset)

Butuh Go >= $MIN_GO_MAJOR.$MIN_GO_MINOR. sudo dipakai hanya bila direktori tujuan
tidak bisa ditulis user saat ini.
EOF
}

# ─── sudo seperlunya ──────────────────────────────────────────────────────────

SUDO=()

# run menjalankan perintah dengan sudo bila memang diperlukan.
run() {
	if ((${#SUDO[@]})); then
		"${SUDO[@]}" "$@"
	else
		"$@"
	fi
}

# nearest_existing_dir: direktori terdekat yang sudah ada (untuk cek izin tulis
# saat BIN_DIR belum ada dan perlu mkdir -p).
nearest_existing_dir() {
	local d="$1"
	while [[ ! -d "$d" ]]; do
		d="$(dirname -- "$d")"
	done
	printf '%s\n' "$d"
}

setup_privileges() {
	if [[ "$(id -u)" -eq 0 ]]; then
		return
	fi
	local probe
	probe="$(nearest_existing_dir "$BIN_DIR")"
	if [[ -w "$probe" ]]; then
		return
	fi
	if ! command -v sudo >/dev/null 2>&1; then
		die "$probe tidak bisa ditulis user $(id -un) dan sudo tidak tersedia. Jalankan sebagai root, atau pilih direktori lain: BINDIR=\$HOME/.local/bin ./install.sh"
	fi
	info "$probe butuh hak root → memakai sudo"
	if ! sudo -v; then
		die "sudo gagal (password salah / tidak ada terminal / bukan sudoer). Jalankan ulang di terminal interaktif, sebagai root, atau dengan BINDIR=\$HOME/.local/bin"
	fi
	SUDO=(sudo)
}

# ─── PATH ─────────────────────────────────────────────────────────────────────

# list_path_copies menampilkan setiap $NAME yang bisa dieksekusi di PATH.
list_path_copies() {
	local dir f ver seen=""
	local IFS=':'
	for dir in $PATH; do
		[[ -n "$dir" ]] || dir="."
		f="$dir/$NAME"
		[[ -f "$f" && -x "$f" ]] || continue
		case ":$seen:" in *":$f:"*) continue ;; esac
		seen="$seen:$f"
		ver="$("$f" -version 2>/dev/null | head -n1 || true)"
		if [[ -L "$f" ]]; then
			printf '      %s -> %s  (%s)\n' "$f" "$(readlink -f -- "$f" 2>/dev/null || readlink -- "$f")" "${ver:-versi tidak terbaca}"
		else
			printf '      %s  (%s)\n' "$f" "${ver:-versi tidak terbaca}"
		fi
	done
}

check_path_resolution() {
	hash -r 2>/dev/null || true
	local found
	found="$(command -v "$NAME" 2>/dev/null || true)"
	if [[ -z "$found" ]]; then
		warn "$BIN_DIR tidak ada di PATH — '$NAME' belum bisa dipanggil tanpa path lengkap. Tambahkan $BIN_DIR ke PATH (script ini tidak mengubah shell rc)."
		return
	fi
	if [[ "$found" -ef "$DEST" ]]; then
		info "PATH OK: '$NAME' → $found"
		local others
		others="$(list_path_copies | grep -vF -- "      $found " || true)"
		if [[ -n "$others" ]]; then
			info "salinan lain di PATH (tertutup oleh $found, tidak terpakai):"
			printf '%s\n' "$others"
		fi
		return
	fi
	warn "'$NAME' di PATH menunjuk ke $found, BUKAN $DEST — versi yang baru dipasang TIDAK akan terpakai."
	warn "Semua salinan di PATH (urutan prioritas):"
	list_path_copies >&2
	warn "Hapus/ganti nama salinan yang mendahului $DEST (script ini tidak menghapusnya otomatis), lalu jalankan: hash -r"
}

# ─── Go ───────────────────────────────────────────────────────────────────────

check_go() {
	if ! command -v go >/dev/null 2>&1; then
		die "Go tidak ditemukan di PATH. Install Go >= $MIN_GO_MAJOR.$MIN_GO_MINOR dulu (Arch: pacman -S go · Debian/Ubuntu: https://go.dev/doc/install), lalu jalankan ulang ./install.sh"
	fi
	local gv
	gv="$(go env GOVERSION 2>/dev/null || true)"
	if [[ -z "$gv" ]]; then
		gv="$(go version 2>/dev/null | awk '{print $3}' || true)"
	fi
	if [[ "$gv" =~ ^go([0-9]+)\.([0-9]+) ]]; then
		local major="${BASH_REMATCH[1]}" minor="${BASH_REMATCH[2]}"
		if ((major < MIN_GO_MAJOR || (major == MIN_GO_MAJOR && minor < MIN_GO_MINOR))); then
			die "Go terlalu lama: $gv ($(command -v go)). Butuh >= go$MIN_GO_MAJOR.$MIN_GO_MINOR. Upgrade Go lalu jalankan ulang."
		fi
		info "Go: $gv ($(command -v go))"
	else
		warn "versi Go tidak dikenali ('${gv:-kosong}') — lanjut build; gagal build berarti Go perlu diperbarui"
	fi
}

# ─── aksi ─────────────────────────────────────────────────────────────────────

WORKDIR=""
cleanup() {
	if [[ -n "$WORKDIR" && -d "$WORKDIR" ]]; then
		rm -rf -- "$WORKDIR"
	fi
}

do_uninstall() {
	if [[ ! -e "$DEST" && ! -L "$DEST" ]]; then
		info "$DEST tidak ada — tidak ada yang dihapus"
	else
		if [[ -d "$DEST" && ! -L "$DEST" ]]; then
			die "$DEST adalah direktori — tidak disentuh"
		fi
		setup_privileges
		run rm -f -- "$DEST"
		info "dihapus: $DEST"
	fi
	hash -r 2>/dev/null || true
	local left
	left="$(list_path_copies)"
	if [[ -n "$left" ]]; then
		warn "masih ada salinan $NAME lain di PATH (tidak disentuh):"
		printf '%s\n' "$left" >&2
	fi
}

do_install() {
	if [[ ! -f "$SCRIPT_DIR/go.mod" ]]; then
		die "go.mod tidak ditemukan di $SCRIPT_DIR — jalankan install.sh dari clone repo secrethunter2"
	fi
	if [[ -d "$DEST" && ! -L "$DEST" ]]; then
		die "$DEST adalah direktori — hapus/pindahkan dulu"
	fi
	check_go
	setup_privileges # gagal-cepat sebelum build bila tujuan tak bisa ditulis

	WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/$NAME-install.XXXXXX")"
	trap cleanup EXIT
	local tmpdir="$WORKDIR"

	info "build dari $SCRIPT_DIR ..."
	# GOTOOLCHAIN=local: jangan pernah men-download toolchain Go lain.
	if ! (cd -- "$SCRIPT_DIR" && GOTOOLCHAIN=local go build -trimpath -o "$tmpdir/$NAME" .); then
		die "build gagal — $DEST tidak diubah"
	fi
	local newver
	if ! newver="$("$tmpdir/$NAME" -version 2>&1)"; then
		die "biner hasil build tidak bisa dijalankan ($newver) — $DEST tidak diubah"
	fi
	info "hasil build: $newver"

	run mkdir -p -- "$BIN_DIR"
	if [[ -L "$DEST" ]]; then
		info "$DEST berupa symlink → $(readlink -- "$DEST"); symlink dihapus (target-nya tidak disentuh)"
		run rm -f -- "$DEST"
	fi
	run install -m 755 -- "$tmpdir/$NAME" "$DEST"
	info "terpasang: $DEST"

	local got
	if ! got="$("$DEST" -version 2>&1)"; then
		die "verifikasi gagal: '$DEST -version' error: $got"
	fi
	info "verifikasi: $DEST -version → $got"
	check_path_resolution
}

main() {
	local action="install"
	while (($#)); do
		case "$1" in
		--uninstall) action="uninstall" ;;
		-h | --help)
			usage
			exit 0
			;;
		*)
			printf '[x] ERROR: opsi tidak dikenal: %s\n\n' "$1" >&2
			usage >&2
			exit 2
			;;
		esac
		shift
	done
	if [[ "$action" == "uninstall" ]]; then
		do_uninstall
	else
		do_install
	fi
}

main "$@"

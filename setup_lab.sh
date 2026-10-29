#!/usr/bin/env bash
# =============================================================================
#  setup_lab.sh - Cài đặt môi trường thực hành
#  Chương trình đào tạo Đội phòng thủ (Blue Team) 2026
#
#  Làm thay toàn bộ phần cấu hình ở Phụ lục A tài liệu học viên trên một máy ảo
#  Kali Linux, Ubuntu hoặc Debian: Wazuh 4.14 all-in-one, tài khoản labuser,
#  SSH bằng mật khẩu,
#  Wazuh đọc auth.log, FIM, nguồn dữ liệu và bộ rule Night Shift.
#  Cố ý KHÔNG làm hai việc: không nạp dữ liệu Night Shift (bước A.6, làm
#  trong giờ nghỉ bằng lệnh lab-nightshift) và không thêm rule 100100
#  (học viên tự thêm ở Bài thực hành 2).
#
#  Cách chạy (một lệnh, trên máy ảo):
#    curl -fsSL <URL>/setup_lab.sh -o setup_lab.sh && sudo bash setup_lab.sh
#
#  Tùy chọn:
#    --pass <mật khẩu>   mật khẩu tài khoản labuser (mặc định Lab@2026)
#    --whitelist <IP>    IP không bao giờ bị active response chặn
#                        (mặc định: IP của máy đang SSH vào)
#    --foreground        chạy trực tiếp, không chạy nền
#    --check             chỉ kiểm tra môi trường đã cài
#    -h, --help          xem hướng dẫn
#
#  Chạy lại nhiều lần không sao: bước nào đã xong thì được bỏ qua.
# =============================================================================
set -Eeuo pipefail

LAB_NAME="Blue Team Lab 2026"
WAZUH_SERIES="4.14"
WAZUH_URL="https://packages.wazuh.com/${WAZUH_SERIES}/wazuh-install.sh"
LAB_USER="labuser"
LAB_PASS="${LAB_PASS:-Lab@2026}"
WHITELIST_IP="${WHITELIST_IP:-}"
LAB_DIR="/opt/blueteam-lab"
LOG="/var/log/blueteam-lab-setup.log"
INFO="/root/blueteam-lab-info.txt"
STATE="${LAB_DIR}/state"
ENV_FILE="${LAB_DIR}/setup.env"
UNIT="blueteam-lab-setup"
OSSEC="/var/ossec/etc/ossec.conf"
RULES="/var/ossec/etc/rules/local_rules.xml"
NS_LOG="/var/log/lab/nightshift.json"
APT=(apt-get -y -qq -o DPkg::Lock::Timeout=600)
MODE="detach"
STEP=""

SSH_SAMPLE='Oct  9 10:05:32 lnx01 sshd[1234]: Failed password for root from 10.10.10.99 port 50211 ssh2'
NS_SAMPLE='{"lab": "nightshift", "ns_time": "2026-10-07T00:43:00Z", "ns_source": "endpoint", "ns_host": "WS12", "ns_user": "user12", "ns_event": "sysmon1", "ns_detail": "Image=powershell.exe parent=WINWORD.EXE cmd=-enc <DA_RUT_GON> signed=yes(Microsoft)"}'

C_OK=$'\e[32m'; C_WARN=$'\e[33m'; C_ERR=$'\e[31m'; C_B=$'\e[1m'; C_0=$'\e[0m'

say()  { printf '%s\n' "$*"; }
step() { STEP="$1"; printf '\n%s[%s UTC] %s%s\n' "$C_B" "$(date -u +%H:%M:%S)" "$1" "$C_0"; }
ok()   { printf '  %sOK%s     %s\n' "$C_OK" "$C_0" "$*"; }
warn() { printf '  %sCHÚ Ý%s  %s\n' "$C_WARN" "$C_0" "$*"; }
die()  { printf '\n%sLỖI:%s %s\n' "$C_ERR" "$C_0" "$*"; exit 1; }

usage() {
  sed -n '3,25p' "$0" 2>/dev/null | sed 's/^# \{0,2\}//' || true
}

need_root() {
  [ "$(id -u)" -eq 0 ] || die "Cần quyền root. Chạy lại: sudo bash setup_lab.sh"
}

parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --pass)       [ $# -ge 2 ] || die "Thiếu mật khẩu sau --pass"; LAB_PASS="$2"; shift 2 ;;
      --whitelist)  [ $# -ge 2 ] || die "Thiếu IP sau --whitelist"; WHITELIST_IP="$2"; shift 2 ;;
      --foreground) MODE="foreground"; shift ;;
      --check)      MODE="check"; shift ;;
      --run)        MODE="run"; shift ;;
      -h|--help)    usage; exit 0 ;;
      *)            die "Không hiểu tùy chọn: $1 (xem: bash setup_lab.sh --help)" ;;
    esac
  done
}

is_ipv4() { [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; }

vm_ip() {
  local ip
  ip=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "src") { print $(i + 1); exit }}')
  [ -n "$ip" ] || ip=$(hostname -I 2>/dev/null | awk '{print $1}')
  printf '%s' "${ip:-<IP_MAY_AO>}"
}

client_ip() {
  local ip="${SSH_CLIENT:-}"
  ip="${ip%% *}"
  [ -n "$ip" ] || ip=$(who -m 2>/dev/null | sed -n 's/.*(\([0-9.]*\)).*/\1/p')
  is_ipv4 "$ip" && printf '%s' "$ip" || true
}

mem_mb() { awk '/MemTotal/ { printf "%d", $2 / 1024 }' /proc/meminfo; }

# Dưới 7 GB RAM thì bật chế độ tiết kiệm bộ nhớ: thêm swap, tắt quét lỗ hổng
low_mem() { [ "$(mem_mb)" -lt 7000 ]; }

wazuh_ok() {
  local s
  for s in wazuh-indexer wazuh-manager wazuh-dashboard; do
    systemctl is-active --quiet "$s" || return 1
  done
}

wazuh_pkg_any() {
  local p
  for p in wazuh-manager wazuh-indexer wazuh-dashboard; do
    dpkg -s "$p" >/dev/null 2>&1 && return 0
  done
  return 1
}

wazuh_pkg_all() {
  local p
  for p in wazuh-manager wazuh-indexer wazuh-dashboard; do
    dpkg -s "$p" >/dev/null 2>&1 || return 1
  done
}

# Mật khẩu admin của Dashboard nằm trong gói wazuh-install-files.tar do bộ cài tạo ra
admin_pass() {
  local t p home=""
  [ -n "${SUDO_USER:-}" ] && home=$(getent passwd "$SUDO_USER" | cut -d: -f6)
  for t in "$LAB_DIR/wazuh-install-files.tar" /root/wazuh-install-files.tar "${home:-/nonexistent}/wazuh-install-files.tar"; do
    [ -f "$t" ] || continue
    p=$(tar -xOf "$t" wazuh-install-files/wazuh-passwords.txt 2>/dev/null \
        | awk '/indexer_username: \047admin\047/ { getline; sub(/^[^\047]*\047/, ""); sub(/\047.*$/, ""); print; exit }') || true
    if [ -n "$p" ]; then printf '%s' "$p"; return 0; fi
  done
  printf '%s' "(không đọc được, dùng mật khẩu đã ghi khi cài Wazuh)"
}

# Đưa một dòng log vào wazuh-logtest, trả về 0 nếu kết quả có rule mong muốn
logtest_has() {
  local line="$1" rule="$2" out="" i
  for i in 1 2 3 4 5 6; do
    out=$(printf '%s\n' "$line" | timeout 30 /var/ossec/bin/wazuh-logtest 2>&1) || true
    [[ "$out" == *"id: '$rule'"* ]] && return 0
    [[ "$out" == *"Phase 3"* ]] && return 1
    sleep 5
  done
  return 1
}

# ----------------------------------------------------------------------------
# Kiểm tra trước khi cài
# ----------------------------------------------------------------------------
preflight() {
  need_root
  say "${C_B}${LAB_NAME} - cài đặt môi trường thực hành${C_0}"
  step "Kiểm tra máy ảo"

  [ -r /etc/os-release ] || die "Không xác định được hệ điều hành"
  # shellcheck disable=SC1091
  . /etc/os-release
  case "${ID:-}" in
    kali)
      ok "Hệ điều hành: ${PRETTY_NAME:-Kali}"
      warn "Kali không nằm trong danh sách Wazuh khuyến nghị. Bộ cài sẽ in cảnh báo này, vẫn cài bình thường." ;;
    ubuntu|debian) ok "Hệ điều hành: ${PRETTY_NAME:-$ID}" ;;
    *) die "Script chỉ chạy trên Kali Linux, Ubuntu hoặc Debian (máy này: ${PRETTY_NAME:-không rõ})" ;;
  esac
  [ -d /run/systemd/system ] || die "Máy không chạy systemd. Cần máy ảo cài đầy đủ, không dùng container hay WSL."

  local cpu mb disk
  cpu=$(nproc)
  mb=$(mem_mb)
  disk=$(df -BG --output=avail / | tail -1 | tr -dc '0-9')
  [ "$cpu" -ge 2 ] || die "Máy ảo có $cpu CPU, Wazuh cần tối thiểu 2 (khuyến nghị 4)"
  [ "$mb" -ge 3000 ] || die "Máy ảo chỉ có ${mb} MB RAM. Cần tối thiểu 4 GB (khuyến nghị 8 GB), tắt máy ảo, tăng RAM rồi chạy lại."
  [ "$disk" -ge 20 ] || die "Ổ / chỉ còn ${disk} GB trống, cần tối thiểu 20 GB (khuyến nghị 50 GB)"
  ok "Cấu hình: ${cpu} CPU, ${mb} MB RAM, ${disk} GB trống"
  if low_mem; then
    warn "RAM dưới 8 GB, bật chế độ tiết kiệm bộ nhớ: thêm swap 4 GB, tắt module quét lỗ hổng (khóa học không dùng)."
    warn "Với 4 GB RAM, nên mở Dashboard từ trình duyệt máy thật thay vì Firefox trong máy ảo."
  fi
  [ "$cpu" -ge 4 ] || warn "Dưới 4 CPU, quá trình cài sẽ lâu hơn"

  if wazuh_ok; then
    ok "Wazuh đã cài sẵn và đang chạy"
  else
    if ! wazuh_pkg_any && ss -ltnH 'sport = :443' 2>/dev/null | grep -q .; then
      die "Cổng 443 đang bị chương trình khác dùng, Dashboard Wazuh sẽ không chạy được. Xem: sudo ss -ltnp 'sport = :443'"
    fi
    curl -fsSI --max-time 20 "$WAZUH_URL" >/dev/null \
      || die "Máy ảo không tải được từ packages.wazuh.com. Kiểm tra mạng, DNS, proxy rồi chạy lại."
    ok "Kết nối được tới packages.wazuh.com"
  fi

  if [ -z "$WHITELIST_IP" ]; then WHITELIST_IP=$(client_ip); fi
  if [ -n "$WHITELIST_IP" ]; then
    is_ipv4 "$WHITELIST_IP" || die "IP whitelist không hợp lệ: $WHITELIST_IP"
    ok "IP được miễn chặn (active response): $WHITELIST_IP"
  fi
  ok "Tài khoản thực hành: $LAB_USER / $LAB_PASS"
}

# ----------------------------------------------------------------------------
# Các bước cài đặt
# ----------------------------------------------------------------------------
install_base() {
  step "1/9 Cài gói cơ bản và đồng bộ thời gian"
  export DEBIAN_FRONTEND=noninteractive
  "${APT[@]}" update
  "${APT[@]}" install curl tar gnupg apt-transport-https lsb-release ca-certificates \
    openssh-server tcpdump rsyslog python3 >/dev/null
  ok "Đã có openssh-server, tcpdump, rsyslog, python3"

  # Kali và các bản Debian mới chỉ ghi log vào journald, rsyslog mới tạo ra /var/log/auth.log.
  # Ép kiểu thời gian truyền thống (Oct  9 10:05:32) cho giống dòng log mẫu trong bài giảng.
  if [ ! -f /etc/rsyslog.d/00-lab-traditional.conf ]; then
    printf '# %s: ghi log theo kiểu thời gian truyền thống\n$ActionFileDefaultTemplate RSYSLOG_TraditionalFileFormat\n' \
      "$LAB_NAME" > /etc/rsyslog.d/00-lab-traditional.conf
    if ! rsyslogd -N1 >/dev/null 2>&1; then
      rm -f /etc/rsyslog.d/00-lab-traditional.conf
      warn "rsyslog không nhận kiểu thời gian truyền thống, giữ kiểu mặc định"
    fi
  fi
  systemctl enable rsyslog >/dev/null 2>&1 || true
  systemctl restart rsyslog
  logger -p auth.info "${LAB_NAME}: kiem tra auth.log" && sleep 1
  [ -f /var/log/auth.log ] || die "rsyslog không tạo ra /var/log/auth.log. Xem: sudo systemctl status rsyslog"
  ok "rsyslog đang ghi /var/log/auth.log"

  if ! timedatectl set-ntp true 2>/dev/null; then
    # Máy chưa có dịch vụ đồng bộ giờ nào (hay gặp trên Kali): cài systemd-timesyncd
    if ! dpkg -s chrony >/dev/null 2>&1 && ! dpkg -s ntpsec >/dev/null 2>&1 && ! dpkg -s ntp >/dev/null 2>&1; then
      "${APT[@]}" install systemd-timesyncd >/dev/null || true
    fi
  fi
  if timedatectl set-ntp true 2>/dev/null; then
    ok "Đã bật đồng bộ thời gian (NTP)"
  else
    warn "Không bật được NTP, kiểm tra lại bằng lệnh: timedatectl"
  fi
  if low_mem; then setup_swap; fi
}

# Máy ít RAM: thêm swap để Wazuh không bị hệ điều hành tắt khi thiếu bộ nhớ
setup_swap() {
  local swap_mb
  swap_mb=$(awk '/SwapTotal/ { printf "%d", $2 / 1024 }' /proc/meminfo)
  if [ "$swap_mb" -ge 2000 ]; then
    ok "Máy đã có ${swap_mb} MB swap, không cần thêm"
  elif [ -f /swapfile-lab ]; then
    swapon /swapfile-lab 2>/dev/null || true
    ok "Đã bật lại /swapfile-lab"
  else
    fallocate -l 4G /swapfile-lab 2>/dev/null || dd if=/dev/zero of=/swapfile-lab bs=1M count=4096 status=none
    chmod 600 /swapfile-lab
    mkswap /swapfile-lab >/dev/null
    swapon /swapfile-lab
    grep -q '^/swapfile-lab ' /etc/fstab || echo '/swapfile-lab none swap sw 0 0' >> /etc/fstab
    ok "Đã thêm 4 GB swap (/swapfile-lab), giữ nguyên sau khi khởi động lại"
  fi
  # Chỉ dùng swap khi thật sự thiếu RAM, để Wazuh không bị chậm
  printf 'vm.swappiness=10\n' > /etc/sysctl.d/99-blueteam-lab.conf
  sysctl -q -p /etc/sysctl.d/99-blueteam-lab.conf || true
}

install_wazuh() {
  step "2/9 Cài Wazuh ${WAZUH_SERIES} all-in-one (bước lâu nhất, khoảng 10 - 20 phút)"
  if wazuh_ok; then
    ok "Wazuh đã cài và đang chạy, bỏ qua bước này"
    return 0
  fi
  if wazuh_pkg_all; then
    warn "Wazuh đã cài nhưng có dịch vụ đang dừng, thử khởi động lại"
    systemctl start wazuh-indexer wazuh-manager wazuh-dashboard || true
    sleep 20
    if wazuh_ok; then
      ok "Wazuh đã chạy lại bình thường"
      return 0
    fi
  fi
  cd "$LAB_DIR"
  curl -fsSL --retry 3 -o wazuh-install.sh "$WAZUH_URL"
  local args=(-a)
  if wazuh_pkg_any; then
    args+=(-o)
    warn "Thấy Wazuh cài dở từ lần trước, cài đè lên"
  fi
  # Bộ cài Wazuh dừng nếu RAM dưới 3700 MB; máy ảo "4 GB" thường chỉ báo 3600 - 3900 MB
  if [ "${WAZUH_IGNORE_CHECKS:-0}" = 1 ] || [ "$(mem_mb)" -lt 3700 ]; then
    args+=(-i)
    warn "RAM sát mức tối thiểu, cho bộ cài Wazuh bỏ qua bước kiểm tra phần cứng (-i)"
  fi
  bash ./wazuh-install.sh "${args[@]}"
  wazuh_ok || die "Bộ cài Wazuh đã chạy xong nhưng dịch vụ chưa lên đủ. Xem /var/log/wazuh-install.log"
  [ -f "$LAB_DIR/wazuh-install-files.tar" ] && chmod 600 "$LAB_DIR/wazuh-install-files.tar"
  ok "Wazuh indexer, manager, dashboard đều đang chạy"
}

setup_labuser() {
  step "3/9 Tạo tài khoản thực hành ${LAB_USER}"
  if id "$LAB_USER" >/dev/null 2>&1; then
    ok "Tài khoản $LAB_USER đã có"
  else
    useradd -m -s /bin/bash "$LAB_USER"
    ok "Đã tạo tài khoản $LAB_USER"
  fi
  printf '%s:%s\n' "$LAB_USER" "$LAB_PASS" | chpasswd
  install -d -m 700 -o "$LAB_USER" -g "$(id -gn "$LAB_USER")" "/home/${LAB_USER}/.ssh"
  ok "Đã đặt mật khẩu và tạo /home/${LAB_USER}/.ssh"
}

# Giá trị PasswordAuthentication sshd đang dùng thật (rỗng nếu sshd -T không đọc được)
ssh_pw_auth() {
  local v
  v=$(sshd -T -C "user=${LAB_USER},host=localhost,addr=127.0.0.1" 2>/dev/null | awk '/^passwordauthentication/ { print $2; exit }') || true
  [ -n "$v" ] || v=$(sshd -T 2>/dev/null | awk '/^passwordauthentication/ { print $2; exit }') || true
  printf '%s' "$v"
}

ssh_reload() {
  sshd -t || die "Cấu hình SSH bị lỗi, xem thông báo ở trên"
  systemctl enable ssh >/dev/null 2>&1 || true
  systemctl restart ssh 2>/dev/null || systemctl restart sshd
}

setup_ssh() {
  step "4/9 Cho phép SSH bằng mật khẩu (chỉ dùng trong lab)"
  install -d /etc/ssh/sshd_config.d /run/sshd
  # sshd lấy giá trị gặp đầu tiên; tên 00-0-... đứng trước mọi tệp khác trong sshd_config.d
  rm -f /etc/ssh/sshd_config.d/00-lab.conf
  printf '# %s: cho phép đăng nhập SSH bằng mật khẩu để thực hành\nPasswordAuthentication yes\n' \
    "$LAB_NAME" > /etc/ssh/sshd_config.d/00-0-blueteam-lab.conf
  if ! grep -qE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' /etc/ssh/sshd_config; then
    sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' /etc/ssh/sshd_config
  fi
  ssh_reload

  local v f
  v=$(ssh_pw_auth)
  if [ "$v" = no ]; then
    # Còn tệp khác đặt "no" và được đọc trước: vô hiệu các dòng đó (có lưu bản gốc .lab-bak)
    for f in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf; do
      [ -f "$f" ] || continue
      case "$f" in */00-0-blueteam-lab.conf) continue ;; esac
      if grep -qiE '^[[:space:]]*PasswordAuthentication[[:space:]]+no' "$f"; then
        [ -f "$f.lab-bak" ] || cp -p "$f" "$f.lab-bak"
        sed -i -E 's/^([[:space:]]*)(PasswordAuthentication[[:space:]]+no)/\1# Blue Team Lab: \2/I' "$f"
        warn "Đã tắt dòng 'PasswordAuthentication no' trong $f (bản gốc: $f.lab-bak)"
      fi
    done
    ssh_reload
    v=$(ssh_pw_auth)
  fi

  case "$v" in
    yes)
      ok "passwordauthentication yes" ;;
    no)
      say "         Các dòng PasswordAuthentication đang có:"
      grep -rniH 'PasswordAuthentication' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/ 2>/dev/null | sed 's/^/           /' || true
      die "SSH vẫn chưa cho đăng nhập bằng mật khẩu, xem các dòng ở trên" ;;
    *)
      # sshd -T không in được cấu hình (gặp trên vài bản OpenSSH mới); mặc định của OpenSSH là yes
      warn "Không đọc được cấu hình hiệu lực bằng 'sshd -T', vẫn tiếp tục vì tệp lab đã đặt PasswordAuthentication yes"
      sshd -T 2>&1 >/dev/null | head -3 | sed 's/^/           /' || true ;;
  esac
}

setup_ossec() {
  step "5/9 Cấu hình Wazuh: auth.log, FIM, nguồn dữ liệu Night Shift, whitelist"
  install -d -m 755 /var/log/lab
  [ -f "$NS_LOG" ] || install -m 644 /dev/null "$NS_LOG"
  [ -f "$OSSEC.lab-orig" ] || cp -p "$OSSEC" "$OSSEC.lab-orig"
  cp -p "$OSSEC" "$OSSEC.lab-prev"
  local lowmem=0
  if low_mem; then lowmem=1; fi
  OSSEC="$OSSEC" WL="$WHITELIST_IP" NS_LOG="$NS_LOG" LAB_USER="$LAB_USER" LOWMEM="$lowmem" python3 - <<'PY'
import os, re
path, wl, ns, user = os.environ["OSSEC"], os.environ.get("WL", "").strip(), os.environ["NS_LOG"], os.environ["LAB_USER"]
lowmem = os.environ.get("LOWMEM") == "1"
with open(path, encoding="utf-8") as f:
    s = f.read()
orig, notes = s, []

def has_location(loc):
    return re.search(r"<location>\s*" + re.escape(loc) + r"\s*</location>", s) is not None

def before_last_close(block):
    global s
    i = s.rfind("</ossec_config>")
    if i < 0:
        raise SystemExit("ossec.conf thiếu thẻ </ossec_config>")
    s = s[:i] + block + s[i:]

if not has_location("/var/log/auth.log"):
    before_last_close("  <!-- Blue Team Lab: auth.log cho Bài 1, 2 -->\n  <localfile>\n    <log_format>syslog</log_format>\n"
                      "    <location>/var/log/auth.log</location>\n  </localfile>\n\n")
    notes.append("thêm nguồn /var/log/auth.log")
if not has_location(ns):
    before_last_close("  <!-- Blue Team Lab: nguồn Night Shift cho Bài 3 -->\n  <localfile>\n    <log_format>json</log_format>\n"
                      "    <location>" + ns + "</location>\n  </localfile>\n\n")
    notes.append("thêm nguồn " + ns)
fim = "/home/%s/.ssh" % user
if fim not in s:
    m = re.search(r"<syscheck>", s)
    if not m:
        raise SystemExit("ossec.conf không có khối <syscheck>")
    add = ("\n    <!-- Blue Team Lab: FIM cho bài B.2 -->"
           '\n    <directories realtime="yes" check_all="yes" report_changes="yes">/etc/cron.d</directories>'
           '\n    <directories realtime="yes" check_all="yes" report_changes="yes">' + fim + "</directories>")
    s = s[:m.end()] + add + s[m.end():]
    notes.append("thêm FIM thời gian thực cho /etc/cron.d và " + fim)
# 127.0.0.1 luôn được miễn chặn: Bài thực hành 2 dò mật khẩu vào chính máy này qua 127.0.0.1
for ip in ["127.0.0.1"] + ([wl] if wl else []):
    if ("<white_list>%s</white_list>" % ip) in s:
        continue
    m = re.search(r"<global>", s)
    if not m:
        raise SystemExit("ossec.conf không có khối <global>")
    s = s[:m.end()] + "\n    <white_list>%s</white_list>" % ip + s[m.end():]
    notes.append("thêm %s vào white_list" % ip)
# Quét lỗ hổng tải và lập chỉ mục cả kho CVE, tốn nhiều RAM; khóa học không dùng module này
if lowmem:
    # Chỉ tìm <enabled> nằm bên trong khối <vulnerability-detection>, không lấn sang khối khác
    pat = re.compile(r"(<vulnerability-detection>(?:(?!</vulnerability-detection>).)*?<enabled>)\s*yes\s*(</enabled>)", re.S)
    if pat.search(s):
        s = pat.sub(r"\1no\2", s, count=1)
        notes.append("tắt module quét lỗ hổng (tiết kiệm RAM)")

if s != orig:
    with open(path, "w", encoding="utf-8") as f:
        f.write(s)
for n in notes:
    print("  OK     " + n)
if not notes:
    print("  OK     ossec.conf đã đủ cấu hình, không cần sửa")
active = re.sub(r"<!--.*?-->", "", s, flags=re.S)
for blk in re.findall(r"<active-response>(.*?)</active-response>", active, flags=re.S):
    if "firewall-drop" in blk:
        print("  CHÚ Ý  Active response firewall-drop đang bật. IP nào không nằm trong white_list"
              " có thể bị chặn khi dò mật khẩu ở Bài thực hành 2.")
        break
if re.search(r"<location>\s*journald\s*</location>", active):
    print("  CHÚ Ý  Wazuh cũng đang đọc journald. Nếu mỗi lần SSH sai sinh ra hai alert 5760,"
          " hãy tắt khối <localfile> journald trong ossec.conf.")
PY
}

setup_rules() {
  step "6/9 Thêm bộ rule Night Shift (100300 - 100306)"
  cp -p "$RULES" "$RULES.lab-prev"
  if grep -q 'id="100300"' "$RULES"; then
    ok "Bộ rule Night Shift đã có, bỏ qua"
  else
    cat >> "$RULES" <<'XML'

<!-- Blue Team Lab 2026: bộ rule cho Bài thực hành 3 -->
<group name="local,lab,nightshift,">
  <rule id="100300" level="3">
    <decoded_as>json</decoded_as>
    <field name="lab">^nightshift$</field>
    <description>Night Shift: $(ns_source) $(ns_event) tren $(ns_host) ($(ns_user))</description>
  </rule>
  <rule id="100301" level="5">
    <if_sid>100300</if_sid>
    <field name="ns_source">^mail$</field>
    <field name="ns_detail">docm</field>
    <description>Night Shift: thu co tep dinh kem chua macro gui toi $(ns_user)</description>
    <mitre><id>T1566.001</id></mitre>
  </rule>
  <rule id="100302" level="6">
    <if_sid>100300</if_sid>
    <field name="ns_event">^sysmon1$</field>
    <field name="ns_detail">powershell</field>
    <description>Night Shift: PowerShell chay tren $(ns_host)</description>
    <mitre><id>T1059.001</id></mitre>
  </rule>
  <rule id="100303" level="12">
    <if_sid>100302</if_sid>
    <field name="ns_detail">parent=WINWORD</field>
    <description>Night Shift: Word sinh PowerShell tren $(ns_host)</description>
    <mitre><id>T1204.002</id></mitre>
  </rule>
  <rule id="100304" level="10">
    <if_sid>100300</if_sid>
    <field name="ns_event">^sysmon13$</field>
    <field name="ns_detail" type="pcre2">\\Run\\</field>
    <description>Night Shift: Run key moi tren $(ns_host)</description>
    <mitre><id>T1547.001</id></mitre>
  </rule>
  <rule id="100305" level="8">
    <if_sid>100300</if_sid>
    <field name="ns_event">^4769$</field>
    <field name="ns_detail">EncType=0x17</field>
    <description>Night Shift: ve dich vu Kerberos RC4 cho $(ns_user)</description>
    <mitre><id>T1558.003</id></mitre>
  </rule>
  <rule id="100306" level="8">
    <if_sid>100300</if_sid>
    <field name="ns_event">^4624$</field>
    <field name="ns_user" type="pcre2">^svc-</field>
    <field name="ns_detail">LogonType=3</field>
    <description>Night Shift: tai khoan dich vu $(ns_user) dang nhap qua mang vao $(ns_host)</description>
    <mitre><id>T1078</id></mitre>
  </rule>
</group>
XML
    ok "Đã thêm 7 rule vào local_rules.xml"
  fi
  if grep -q 'id="100100"' "$RULES"; then
    warn "local_rules.xml đã có rule 100100. Bài thực hành 2 yêu cầu học viên tự thêm rule này, muốn làm lại từ đầu thì xóa nó đi."
  else
    ok "Chưa có rule 100100 (đúng, học viên tự thêm ở Bài thực hành 2)"
  fi
  # Kiểm tra cú pháp toàn bộ cấu hình và rule trước khi khởi động lại manager
  if ! /var/ossec/bin/wazuh-analysisd -t >/dev/null 2>&1; then
    /var/ossec/bin/wazuh-analysisd -t 2>&1 | tail -5 || true
    cp -p "$OSSEC.lab-prev" "$OSSEC"
    cp -p "$RULES.lab-prev" "$RULES"
    die "Cấu hình Wazuh sau khi sửa bị lỗi, đã trả ossec.conf và local_rules.xml về như trước bước 5"
  fi
  ok "wazuh-analysisd -t: cấu hình và rule hợp lệ"
}

setup_tools() {
  step "7/9 Chép dữ liệu Night Shift và cài công cụ lab-check, lab-nightshift"
  install -d -m 755 "$LAB_DIR/data"
  payload | base64 -d | tar -xz --no-same-owner -C "$LAB_DIR/data"
  chmod 644 "$LAB_DIR"/data/*
  [ "$(wc -l < "$LAB_DIR/data/nightshift_sample.json")" -eq 346 ] || die "Dữ liệu Night Shift không đủ 346 dòng"
  ok "Dữ liệu và script nằm ở $LAB_DIR/data"

  # Bản sao trong thư mục home của người chạy script, để làm bài bổ trợ và bài về nhà
  if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ] && [ "$SUDO_USER" != "$LAB_USER" ]; then
    local home
    home=$(getent passwd "$SUDO_USER" | cut -d: -f6)
    if [ -d "$home" ]; then
      install -d -o "$SUDO_USER" -g "$(id -gn "$SUDO_USER")" "$home/lab_night_shift"
      cp "$LAB_DIR"/data/* "$home/lab_night_shift/"
      chown "$SUDO_USER:$(id -gn "$SUDO_USER")" "$home"/lab_night_shift/*
      ok "Bản sao cho $SUDO_USER: $home/lab_night_shift"
    fi
  fi

  cat > /usr/local/bin/lab-nightshift <<'TOOL'
#!/usr/bin/env bash
# Nạp dữ liệu Night Shift cho Bài thực hành 3 (bước A.6). Chỉ nạp một lần.
#   sudo lab-nightshift          xem tệp nguồn đang có bao nhiêu dòng
#   sudo lab-nightshift load     nạp 346 sự kiện
NS_LOG=/var/log/lab/nightshift.json
SRC=/opt/blueteam-lab/data/nightshift_sample.json
ALERTS=/var/ossec/logs/alerts/alerts.json
[ "$(id -u)" -eq 0 ] || { echo "Cần sudo: sudo lab-nightshift ${1:-}"; exit 1; }
n=$(wc -l < "$NS_LOG" 2>/dev/null || echo 0)
case "${1:-status}" in
  status)
    echo "Tệp $NS_LOG đang có $n dòng. Trước giờ nghỉ là 0, nạp xong là 346." ;;
  load)
    if [ "$n" -gt 0 ] && [ "${2:-}" != "--force" ]; then
      echo "Dữ liệu đã được nạp ($n dòng). Nạp lại sẽ bị trùng, Dashboard ra 692 kết quả."
      echo "Nếu vẫn muốn nạp lại: sudo lab-nightshift load --force"
      exit 1
    fi
    systemctl is-active --quiet wazuh-manager || { echo "wazuh-manager chưa chạy: sudo systemctl restart wazuh-manager"; exit 1; }
    before=$(grep -c '"lab":"nightshift"' "$ALERTS" 2>/dev/null || true)
    cat "$SRC" >> "$NS_LOG"
    echo "Đã ghi 346 sự kiện vào $NS_LOG, đang chờ Wazuh xử lý..."
    for _ in $(seq 1 30); do
      sleep 2
      now=$(grep -c '"lab":"nightshift"' "$ALERTS" 2>/dev/null || true)
      [ $(( ${now:-0} - ${before:-0} )) -ge 346 ] && break
    done
    echo "Wazuh đã sinh $(( ${now:-0} - ${before:-0} )) alert Night Shift (đủ là 346)."
    echo "Trên Dashboard: chọn Last 24 hours, truy vấn rule.groups: nightshift" ;;
  *)
    echo "Dùng: sudo lab-nightshift [status|load]"; exit 1 ;;
esac
TOOL

  cat > /usr/local/bin/lab-check <<'TOOL'
#!/usr/bin/env bash
# Kiểm tra nhanh môi trường thực hành Blue Team 2026. Chạy: sudo lab-check
OSSEC=/var/ossec/etc/ossec.conf
RULES=/var/ossec/etc/rules/local_rules.xml
NS_LOG=/var/log/lab/nightshift.json
pass=0; fail=0
good() { printf '  \e[32m[OK]\e[0m   %s\n' "$1"; pass=$((pass + 1)); }
bad()  { printf '  \e[31m[LỖI]\e[0m %s\n         Cách sửa: %s\n' "$1" "$2"; fail=$((fail + 1)); }
info() { printf '  \e[36m[i]\e[0m    %s\n' "$1"; }
logtest_has() {
  local out
  out=$(printf '%s\n' "$1" | timeout 30 /var/ossec/bin/wazuh-logtest 2>&1)
  [[ "$out" == *"id: '$2'"* ]]
}
[ "$(id -u)" -eq 0 ] || { echo "Cần sudo: sudo lab-check"; exit 1; }
echo "Kiểm tra môi trường thực hành Blue Team 2026"
for s in wazuh-indexer wazuh-manager wazuh-dashboard; do
  if systemctl is-active --quiet "$s"; then good "Dịch vụ $s đang chạy"
  else bad "Dịch vụ $s không chạy" "sudo systemctl restart $s, rồi xem sudo journalctl -u $s -n 50"; fi
done
code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 10 https://127.0.0.1/ || true)
case "$code" in
  200|302) good "Dashboard trả lời trên cổng 443" ;;
  *) bad "Dashboard chưa trả lời (mã $code)" "đợi 1 - 2 phút sau khi khởi động rồi thử lại, hoặc sudo systemctl restart wazuh-dashboard" ;;
esac
if [ "$(timedatectl show -p NTPSynchronized --value 2>/dev/null)" = yes ]; then good "Đồng hồ đã đồng bộ"
else bad "Đồng hồ chưa đồng bộ" "sudo timedatectl set-ntp true, đợi vài phút"; fi
if id labuser >/dev/null 2>&1 && [ -d /home/labuser/.ssh ]; then good "Có tài khoản labuser và /home/labuser/.ssh"
else bad "Thiếu tài khoản labuser hoặc thư mục .ssh" "chạy lại setup_lab.sh"; fi
pw=$(sshd -T -C user=labuser,host=localhost,addr=127.0.0.1 2>/dev/null | awk '/^passwordauthentication/ { print $2; exit }')
[ -n "$pw" ] || pw=$(sshd -T 2>/dev/null | awk '/^passwordauthentication/ { print $2; exit }')
case "$pw" in
  yes) good "SSH cho đăng nhập bằng mật khẩu" ;;
  no)  bad "SSH chưa cho đăng nhập bằng mật khẩu" "tìm dòng 'PasswordAuthentication no': sudo grep -rni passwordauthentication /etc/ssh/, sửa thành yes rồi sudo systemctl restart ssh" ;;
  *)   if grep -qi '^PasswordAuthentication yes' /etc/ssh/sshd_config.d/00-0-blueteam-lab.conf 2>/dev/null; then
         info "Không đọc được cấu hình SSH bằng sshd -T, tệp lab đã đặt PasswordAuthentication yes"
       else bad "Chưa cấu hình SSH bằng mật khẩu" "chạy lại setup_lab.sh"; fi ;;
esac
if systemctl is-active --quiet ssh || systemctl is-active --quiet sshd; then good "Dịch vụ SSH đang chạy"
else bad "Dịch vụ SSH không chạy" "sudo systemctl enable --now ssh"; fi
if command -v tcpdump >/dev/null; then good "Đã có tcpdump"; else bad "Chưa có tcpdump" "sudo apt install -y tcpdump"; fi
if [ -f /var/log/auth.log ] && grep -q '<location>/var/log/auth.log</location>' "$OSSEC"; then good "Wazuh đọc /var/log/auth.log"
else bad "Wazuh chưa đọc /var/log/auth.log" "sudo apt install -y rsyslog, rồi chạy lại setup_lab.sh"; fi
if grep -q '/home/labuser/.ssh</directories>' "$OSSEC"; then good "Đã cấu hình FIM thời gian thực"
else bad "Chưa cấu hình FIM" "chạy lại setup_lab.sh"; fi
if [ -f "$NS_LOG" ] && grep -q "<location>$NS_LOG</location>" "$OSSEC"; then good "Đã khai báo nguồn $NS_LOG"
else bad "Chưa khai báo nguồn Night Shift" "chạy lại setup_lab.sh"; fi
if grep -q 'id="100300"' "$RULES"; then good "Đã có bộ rule Night Shift"
else bad "Chưa có bộ rule Night Shift" "chạy lại setup_lab.sh"; fi
if logtest_has 'Oct  9 10:05:32 lnx01 sshd[1234]: Failed password for root from 10.10.10.99 port 50211 ssh2' 5760; then
  good "wazuh-logtest: SSH sai mật khẩu ra rule 5760"
else bad "wazuh-logtest không ra rule 5760" "sudo systemctl restart wazuh-manager, đợi 30 giây rồi thử lại"; fi
if logtest_has '{"lab": "nightshift", "ns_time": "2026-10-07T00:43:00Z", "ns_source": "endpoint", "ns_host": "WS12", "ns_user": "user12", "ns_event": "sysmon1", "ns_detail": "Image=powershell.exe parent=WINWORD.EXE cmd=-enc <DA_RUT_GON> signed=yes(Microsoft)"}' 100303; then
  good "wazuh-logtest: dòng Night Shift ra rule 100303"
else bad "wazuh-logtest không ra rule 100303" "kiểm tra bộ rule trong $RULES, rồi sudo systemctl restart wazuh-manager"; fi
if grep -q 'id="100100"' "$RULES"; then info "Đã có rule 100100 (bình thường nếu đã làm xong Bài thực hành 2)"
else info "Chưa có rule 100100 (đúng trạng thái trước Bài thực hành 2)"; fi
info "Dữ liệu Night Shift: $(wc -l < "$NS_LOG" 2>/dev/null || echo 0) dòng (trước giờ nghỉ là 0, nạp xong là 346)"
echo
if [ "$fail" -eq 0 ]; then printf '\e[32mKết quả: %d mục đều đạt. Môi trường sẵn sàng.\e[0m\n' "$pass"
else printf '\e[31mKết quả: %d đạt, %d lỗi. Sửa theo gợi ý ở trên rồi chạy lại sudo lab-check.\e[0m\n' "$pass" "$fail"; fi
[ "$fail" -eq 0 ]
TOOL
  chmod 755 /usr/local/bin/lab-nightshift /usr/local/bin/lab-check
  ok "Đã cài lệnh: sudo lab-check, sudo lab-nightshift"
}

setup_firewall() {
  step "8/9 Tường lửa trên máy ảo"
  if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q '^Status: active'; then
    local p
    for p in 22 443 1514 1515 55000; do ufw allow "${p}/tcp" >/dev/null; done
    ok "ufw đang bật, đã mở cổng 22, 443, 1514, 1515, 55000"
  else
    ok "ufw không bật, không cần mở cổng"
  fi
}

restart_and_test() {
  step "9/9 Khởi động lại Wazuh manager và kiểm thử"
  local t0 i errs
  t0=$(date '+%Y/%m/%d %H:%M:%S')
  systemctl restart wazuh-manager
  for i in $(seq 1 30); do
    systemctl is-active --quiet wazuh-manager && break
    sleep 2
  done
  systemctl is-active --quiet wazuh-manager \
    || die "wazuh-manager không khởi động lại được. Xem: sudo tail -30 /var/ossec/logs/ossec.log"
  ok "wazuh-manager đang chạy"
  sleep 10
  errs=$(awk -v t="$t0" 'substr($0, 1, 19) >= t && /ERROR|CRITICAL/' /var/ossec/logs/ossec.log 2>/dev/null | tail -5 || true)
  [ -z "$errs" ] || { warn "ossec.log có thông báo lỗi sau khi khởi động lại:"; printf '         %s\n' "$errs"; }
  if logtest_has "$SSH_SAMPLE" 5760; then
    ok "wazuh-logtest: dòng SSH sai mật khẩu ra rule 5760"
  else
    warn "wazuh-logtest chưa ra rule 5760, chạy lại sudo lab-check sau 1 phút"
  fi
  logtest_has "$NS_SAMPLE" 100303 \
    || die "wazuh-logtest không ra rule 100303. Kiểm tra bộ rule Night Shift trong $RULES"
  ok "wazuh-logtest: dòng Night Shift ra rule 100303, level 12"
}

write_info() {
  local ip ap
  ip=$(vm_ip)
  ap=$(admin_pass)
  ( umask 077
    cat > "$INFO" <<EOF
${LAB_NAME} - thông tin máy ảo (tạo lúc $(date -u '+%Y-%m-%d %H:%M') UTC)

Dashboard Wazuh : https://${ip}
  Tài khoản     : admin
  Mật khẩu      : ${ap}

SSH thực hành   : ssh ${LAB_USER}@${ip}
  Mật khẩu      : ${LAB_PASS}

Lệnh hữu ích
  sudo lab-check             kiểm tra lại toàn bộ môi trường
  sudo lab-nightshift load   nạp dữ liệu Bài thực hành 3 (chỉ khi giảng viên yêu cầu)
  sudo cat ${INFO}   xem lại tệp này
EOF
  )
}

summary() {
  local ip
  ip=$(vm_ip)
  printf '\n%s==================== LAB ĐÃ SẴN SÀNG ====================%s\n' "$C_OK" "$C_0"
  sed -n '3,9p' "$INFO"
  printf '\nThông tin trên được lưu ở %s (xem lại: sudo cat %s)\n' "$INFO" "$INFO"
  printf 'Mở trình duyệt ngay trên máy ảo (ví dụ Firefox trên Kali) thì vào https://localhost\n'
  printf 'Trình duyệt sẽ cảnh báo chứng chỉ tự ký, bấm Advanced rồi Accept the Risk (hoặc Proceed) để vào Dashboard.\n'
  printf 'Kiểm tra lại bất cứ lúc nào: sudo lab-check\n'
  if low_mem; then
    printf '%sMáy ảo ít RAM:%s Dashboard mở lần đầu có thể mất 1 - 2 phút. Đóng bớt ứng dụng trong máy ảo,\n' "$C_WARN" "$C_0"
    printf 'tốt nhất mở Dashboard bằng trình duyệt trên máy thật: https://%s\n' "$ip"
  fi
  printf 'Nếu là máy ảo, nên chụp snapshot tên clean-before-training ngay bây giờ.\n'
  printf '%s==========================================================%s\n' "$C_OK" "$C_0"
}

run_all() {
  mkdir -p "$LAB_DIR"
  echo running > "$STATE"
  trap 'printf "         (dòng %s: %s)\n" "$LINENO" "$BASH_COMMAND"' ERR
  trap 'rc=$?
        if [ $rc -eq 0 ]; then echo ok > "$STATE"
        else
          echo failed > "$STATE"
          printf "\n%sCÀI ĐẶT DỪNG Ở BƯỚC: %s%s\n" "$C_ERR" "${STEP:-?}" "$C_0"
          printf "Xem chi tiết: sudo less %s\n" "$LOG"
          printf "Sửa xong thì chạy lại đúng lệnh cũ, bước nào đã xong sẽ được bỏ qua.\n"
        fi
        rm -f "$ENV_FILE"' EXIT
  install_base
  install_wazuh
  setup_labuser
  setup_ssh
  setup_ossec
  setup_rules
  setup_tools
  setup_firewall
  restart_and_test
  write_info
  step "Kiểm tra tổng thể"
  /usr/local/bin/lab-check || warn "Còn mục chưa đạt, xem gợi ý ở trên"
  summary
}

# ----------------------------------------------------------------------------
# Chạy nền bằng systemd, để mất kết nối SSH giữa chừng thì cài đặt vẫn tiếp tục
# ----------------------------------------------------------------------------
can_detach() {
  [ -f "$0" ] && command -v systemd-run >/dev/null
}

start_detached() {
  local self="$LAB_DIR/setup_lab.sh"
  mkdir -p "$LAB_DIR"
  if systemctl is-active --quiet "$UNIT"; then
    warn "Cài đặt đang chạy nền từ lần trước, chỉ mở lại màn hình theo dõi"
  else
    [ "$(readlink -f "$0")" = "$self" ] || cp "$0" "$self"
    chmod 700 "$self"
    ( umask 077
      printf 'LAB_PASS=%q\nWHITELIST_IP=%q\nSUDO_USER=%q\n' "$LAB_PASS" "$WHITELIST_IP" "${SUDO_USER:-}" > "$ENV_FILE" )
    [ -f "$LOG" ] && mv -f "$LOG" "$LOG.1"
    : > "$LOG"
    rm -f "$STATE"
    systemctl reset-failed "$UNIT" >/dev/null 2>&1 || true
    # IgnoreSIGPIPE=no: xử lý SIGPIPE như shell thường, tránh thông báo "tr: write error: Broken pipe"
    # vô hại khi bộ cài Wazuh sinh mật khẩu
    systemd-run --quiet --unit="$UNIT" --description="$LAB_NAME setup" \
      --property=IgnoreSIGPIPE=no \
      --setenv=HOME=/root --setenv=WAZUH_IGNORE_CHECKS="${WAZUH_IGNORE_CHECKS:-0}" \
      /bin/bash "$self" --run
  fi
  printf '\n%sCài đặt đang chạy nền, mất khoảng 15 - 25 phút.%s\n' "$C_B" "$C_0"
  printf 'Lỡ nhấn Ctrl+C hay mất kết nối SSH cũng không sao, cài đặt vẫn tiếp tục.\n'
  printf 'Xem lại tiến độ: sudo tail -f %s\n' "$LOG"

  tail -n +1 -F "$LOG" 2>/dev/null &
  local tp=$!
  trap 'kill '"$tp"' 2>/dev/null; printf "\nĐã thoát màn hình theo dõi, cài đặt vẫn chạy nền.\nXem tiếp: sudo tail -f %s\n" "'"$LOG"'"; exit 0' INT TERM
  while systemctl is-active --quiet "$UNIT"; do sleep 2; done
  sleep 1
  kill "$tp" 2>/dev/null || true
  wait "$tp" 2>/dev/null || true
  trap - INT TERM
  [ "$(cat "$STATE" 2>/dev/null)" = ok ]
}

load_env() {
  # shellcheck disable=SC1090
  [ -f "$ENV_FILE" ] && . "$ENV_FILE"
  return 0
}

# ----------------------------------------------------------------------------
# Dữ liệu Night Shift đóng gói sẵn (tar.gz, base64): night_shift.csv,
# nightshift_sample.json, gen_night_shift.py, ns_helper.py, ns_to_wazuh.py
# ----------------------------------------------------------------------------
payload() {
  cat <<'B64'
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
JBTar8VfHue3w7rd6VzY448P9qcocrZlSwgn+3ziPOci8EZcF/pTLfmE5Jmp30gumvqSkOGmPiTG
xx+yOd7DukRbfO1zZAX7FH6nrh8cCNZ+2m0Hrxy7w0eySGQkJARXOLhdb9fHwwxlxVSHOoiLgrGC
IK62ECizia0/HYxcIVm8b27fSgie1MI4jofTZ0LBcLV/cqKdCbNIGki3wnXnhsTFrUPt5GR/9oQA
JPR9TmgCXLve52hctAd9LnBDM3UC83txWxPhH7Tv3R/GEDy76zva2Ts/cPqffdcN9ubwak58PnZd
0hlXxjTvm3Cgb7U/OBl/3uTDdAOuEziz+8VKTu6Xqzq+X/yedn84jZMnxpM6fib8K+0pSdrimfDX
ek8YHAeHmjsIxBj2tf36t1wzOfDqd3ZvxM2Jw8PJPTFw4SR5ETH/thbFpDYbeG02JvlrKPLD32dS
fydxN07+B4OLe/u/jG5K0wBWyH9EKIrLf4bJTv6vWf7fjN45boost90b7T+dvXyhCfvBl2rBG0k/
2tMbLs4Hbe3ODiM+zlDEeoQP6NYJOPfpan1uXCeCLd/6A64WcGNoj9tYXDrw3+pcVN19g94KfibU
/slHh9pPNSQ9u1pCSu1x6zn6NE59Go+fPr6zvePe4Pq4Z18ez8LSdYHM/p7LAekRK4ojtshMqoV3
dHzp115kTQ1GwUxGSkkSk7xXERHJbw4NowOBTb0z6g/9g5Ux9BiXngudR1n29DXpVyS6HuHtkQB7
hM1HI+wRlg94wzQGH5EOP4i580dcSbL9drd78rnNV+pQ+AZbbkS0u9qfnGhoYiyGcS3hpdTciaHp
a8GA/82XZCdwdtfu2l27a3ftrt21u3bX7tpdu2t37a7dtbt21+7aXbtrd+2u3bW7dtfu2l27a3ft
rt21u3bXo77+P3hyu+sAuAEA
B64
}

main() {
  parse_args "$@"
  case "$MODE" in
    check)
      need_root
      [ -x /usr/local/bin/lab-check ] || die "Chưa cài lab, chạy: sudo bash setup_lab.sh"
      exec /usr/local/bin/lab-check ;;
    run)
      need_root
      load_env
      exec >>"$LOG" 2>&1
      run_all ;;
    foreground)
      preflight
      mkdir -p "$LAB_DIR"
      exec > >(tee -a "$LOG") 2>&1
      run_all ;;
    detach)
      preflight
      if can_detach; then
        start_detached
      else
        mkdir -p "$LAB_DIR"
        exec > >(tee -a "$LOG") 2>&1
        run_all
      fi ;;
  esac
}

main "$@"

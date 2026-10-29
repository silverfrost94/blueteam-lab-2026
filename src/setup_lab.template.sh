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
@@PAYLOAD@@
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

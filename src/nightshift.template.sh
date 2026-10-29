#!/usr/bin/env bash
# =============================================================================
#  nightshift.sh - Tải và nạp dữ liệu "Ca trực đêm" (Night Shift)
#  cho Bài thực hành 3, chương trình đào tạo Đội phòng thủ (Blue Team) 2026
#
#  Dùng trên máy ảo đã cài môi trường bằng setup_lab.sh. Script tự kiểm tra
#  Wazuh đã có nguồn /var/log/lab/nightshift.json và bộ rule 100300 - 100306
#  chưa, thiếu thì thêm vào, rồi nạp 346 sự kiện và chờ Wazuh sinh đủ alert.
#  Dữ liệu được nhúng sẵn trong script, không cần tải thêm tệp nào.
#
#  Cách chạy (một lệnh, trên máy ảo, đầu giờ nghỉ giải lao):
#    curl -fsSL https://raw.githubusercontent.com/silverfrost94/blueteam-lab-2026/main/nightshift.sh -o nightshift.sh && sudo bash nightshift.sh
#
#  Tùy chọn:
#    --status   chỉ xem đã nạp chưa, không nạp
#    --force    nạp thêm một lần nữa dù đã nạp (sự kiện sẽ bị trùng, ra 692)
#
#  Chạy lại nhiều lần không sao: đã nạp rồi thì script chỉ báo kết quả.
# =============================================================================
set -Eeuo pipefail

LAB_DIR="${LAB_DIR:-/opt/blueteam-lab}"
OSSEC="${OSSEC:-/var/ossec/etc/ossec.conf}"
RULES="${RULES:-/var/ossec/etc/rules/local_rules.xml}"
NS_LOG="${NS_LOG:-/var/log/lab/nightshift.json}"
ALERTS="${ALERTS:-/var/ossec/logs/alerts/alerts.json}"
OSSEC_LOG="${OSSEC_LOG:-/var/ossec/logs/ossec.log}"
WAZUH_BIN="${WAZUH_BIN:-/var/ossec/bin}"
TOTAL=346
SETUP_CMD='curl -fsSL https://raw.githubusercontent.com/silverfrost94/blueteam-lab-2026/main/setup_lab.sh -o setup_lab.sh && sudo bash setup_lab.sh'
MODE="load"
FORCE=0
NEED_RESTART=0

C_OK=$'\e[32m'; C_WARN=$'\e[33m'; C_ERR=$'\e[31m'; C_B=$'\e[1m'; C_0=$'\e[0m'

say()  { printf '%s\n' "$*"; }
step() { printf '\n%s%s%s\n' "$C_B" "$1" "$C_0"; }
ok()   { printf '  %sOK%s     %s\n' "$C_OK" "$C_0" "$*"; }
warn() { printf '  %sCHÚ Ý%s  %s\n' "$C_WARN" "$C_0" "$*"; }
die()  { printf '\n%sLỖI:%s %s\n' "$C_ERR" "$C_0" "$*"; exit 1; }

usage() {
  sed -n '3,19p' "$0" | sed 's/^# \{0,1\}//'
}

parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --status)  MODE="status"; shift ;;
      --force)   FORCE=1; shift ;;
      -h|--help) usage; exit 0 ;;
      *) die "Không hiểu tùy chọn: $1 (xem: bash nightshift.sh --help)" ;;
    esac
  done
}

# Số dòng của tệp nguồn, 0 nếu chưa có tệp
ns_lines() {
  if [ -f "$NS_LOG" ]; then wc -l < "$NS_LOG" | tr -d ' '; else echo 0; fi
}

# Số alert Night Shift trong tệp alert của ngày hôm nay
ns_alerts() {
  local n
  n=$(grep -c '"lab":"nightshift"' "$ALERTS" 2>/dev/null) || true
  echo "${n:-0}"
}

manager_active() { systemctl is-active --quiet wazuh-manager; }

# Chờ logcollector mở tệp nguồn sau lần khởi động manager bắt đầu lúc $1
wait_logcollector() {
  local t0="$1" i
  for i in $(seq 1 45); do
    if awk -v t="$t0" -v f="Analyzing file: '$NS_LOG'" \
         'substr($0, 1, 19) >= t && index($0, f) { found = 1 } END { exit !found }' "$OSSEC_LOG" 2>/dev/null; then
      return 0
    fi
    sleep 2
  done
  return 1
}

restart_manager() {
  local t0 i
  t0=$(date '+%Y/%m/%d %H:%M:%S')
  say "         Đang khởi động lại wazuh-manager, chờ khoảng 30 giây..."
  systemctl restart wazuh-manager
  for i in $(seq 1 30); do
    manager_active && break
    sleep 2
  done
  manager_active || die "wazuh-manager không khởi động được. Xem: sudo tail -30 $OSSEC_LOG"
  if wait_logcollector "$t0"; then
    ok "Wazuh đã bắt đầu đọc $NS_LOG"
  else
    warn "Chưa thấy Wazuh báo đọc $NS_LOG trong ossec.log, vẫn thử nạp"
  fi
}

# ----------------------------------------------------------------------------
check_env() {
  [ "$(id -u)" -eq 0 ] || die "Cần quyền quản trị. Chạy lại: sudo bash $0"
  [ -x "$WAZUH_BIN/wazuh-control" ] && [ -f "$OSSEC" ] \
    || die "Máy này chưa có Wazuh. Cài môi trường thực hành trước bằng lệnh:
       $SETUP_CMD"
  command -v python3 >/dev/null || die "Thiếu python3. Cài bằng: sudo apt-get install -y python3"
}

extract_data() {
  step "1/4 Giải nén dữ liệu Night Shift"
  install -d -m 755 "$LAB_DIR/data"
  payload | base64 -d | tar -xz --no-same-owner -C "$LAB_DIR/data"
  chmod 644 "$LAB_DIR"/data/*
  [ "$(wc -l < "$LAB_DIR/data/nightshift_sample.json" | tr -d ' ')" -eq "$TOTAL" ] \
    || die "Dữ liệu trong script không đủ $TOTAL dòng, tải lại script"
  ok "Dữ liệu nằm ở $LAB_DIR/data"
  # Bản sao cho người chạy script, dùng ns_helper.py khi Dashboard chậm
  if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then
    local home
    home=$(getent passwd "$SUDO_USER" | cut -d: -f6)
    if [ -n "$home" ] && [ -d "$home" ]; then
      install -d -o "$SUDO_USER" -g "$(id -gn "$SUDO_USER")" "$home/lab_night_shift"
      cp "$LAB_DIR"/data/* "$home/lab_night_shift/"
      chown "$SUDO_USER:$(id -gn "$SUDO_USER")" "$home"/lab_night_shift/*
      ok "Bản sao cho $SUDO_USER: $home/lab_night_shift"
    fi
  fi
}

# Thêm nguồn log và bộ rule nếu còn thiếu; có thay đổi thì đặt NEED_RESTART=1
ensure_config() {
  step "2/4 Kiểm tra cấu hình Wazuh"
  install -d -m 755 "$(dirname "$NS_LOG")"
  # Tệp nguồn phải có trước khi manager khởi động thì logcollector mới theo dõi
  if [ ! -f "$NS_LOG" ]; then
    touch "$NS_LOG"; chmod 644 "$NS_LOG"; NEED_RESTART=1
    ok "Tạo tệp nguồn $NS_LOG"
  fi

  if grep -Eq "<location>[[:space:]]*${NS_LOG}[[:space:]]*</location>" "$OSSEC"; then
    ok "ossec.conf đã khai báo nguồn $NS_LOG"
  else
    cp -p "$OSSEC" "$OSSEC.ns-prev"
    OSSEC="$OSSEC" NS_LOG="$NS_LOG" python3 - <<'PY'
import os
p, ns = os.environ["OSSEC"], os.environ["NS_LOG"]
s = open(p, encoding="utf-8").read()
i = s.rfind("</ossec_config>")
if i < 0:
    raise SystemExit("ossec.conf thiếu thẻ </ossec_config>")
block = ("  <!-- Blue Team Lab: nguồn Night Shift cho Bài 3 -->\n  <localfile>\n"
         "    <log_format>json</log_format>\n    <location>" + ns + "</location>\n  </localfile>\n\n")
open(p, "w", encoding="utf-8").write(s[:i] + block + s[i:])
PY
    NEED_RESTART=1
    ok "Đã thêm nguồn $NS_LOG vào ossec.conf"
  fi

  if grep -q 'id="100300"' "$RULES" 2>/dev/null; then
    ok "Đã có bộ rule Night Shift (100300 - 100306)"
  else
    [ -f "$RULES" ] && cp -p "$RULES" "$RULES.ns-prev"
    cat >> "$RULES" <<'XML'
@@NSRULES@@
XML
    NEED_RESTART=1
    ok "Đã thêm bộ rule Night Shift (100300 - 100306) vào local_rules.xml"
  fi

  if [ "$NEED_RESTART" -eq 1 ]; then
    if ! "$WAZUH_BIN/wazuh-analysisd" -t >/dev/null 2>&1; then
      "$WAZUH_BIN/wazuh-analysisd" -t 2>&1 | tail -5 || true
      [ -f "$OSSEC.ns-prev" ] && cp -p "$OSSEC.ns-prev" "$OSSEC"
      [ -f "$RULES.ns-prev" ] && cp -p "$RULES.ns-prev" "$RULES"
      die "Cấu hình Wazuh sau khi sửa bị lỗi, đã trả ossec.conf và local_rules.xml về như cũ.
       Kiểm tra lỗi ở trên, hoặc chạy sudo lab-check"
    fi
    ok "wazuh-analysisd -t: cấu hình và rule hợp lệ"
  fi
}

load_data() {
  step "4/4 Nạp $TOTAL sự kiện vào Wazuh"
  local before now i
  before=$(ns_alerts)
  cat "$LAB_DIR/data/nightshift_sample.json" >> "$NS_LOG"
  say "         Đã ghi $TOTAL sự kiện vào $NS_LOG, đang chờ Wazuh xử lý..."
  now=$before
  for i in $(seq 1 45); do
    sleep 2
    now=$(ns_alerts)
    [ $((now - before)) -ge "$TOTAL" ] && break
  done
  if [ $((now - before)) -ge "$TOTAL" ]; then
    ok "Wazuh đã sinh $((now - before)) alert Night Shift (đủ là $TOTAL)"
  else
    warn "Wazuh mới sinh $((now - before)) / $TOTAL alert. Đợi thêm một phút rồi xem trên Dashboard."
    warn "Nếu vẫn thiếu, chạy sudo lab-check và báo giảng viên."
  fi
}

show_status() {
  local n
  n=$(ns_lines)
  say "Tệp nguồn $NS_LOG: $n dòng (chưa nạp là 0, nạp xong là $TOTAL)"
  say "Alert Night Shift trong tệp alert hôm nay: $(ns_alerts)"
  if manager_active; then say "wazuh-manager: đang chạy"; else say "wazuh-manager: KHÔNG chạy"; fi
  if [ "$n" -gt 0 ]; then say "=> Đã nạp."; else say "=> Chưa nạp. Chạy: sudo bash nightshift.sh"; fi
}

dashboard_hint() {
  printf '\n%s==================== ĐÃ NẠP DỮ LIỆU CA TRỰC ĐÊM ====================%s\n' "$C_OK" "$C_0"
  say "Trên Dashboard (https://localhost): Threat intelligence > Threat Hunting > Events"
  say "  Chọn khoảng thời gian Last 24 hours, truy vấn:  rule.groups: nightshift"
  say "  Kết quả đúng: $TOTAL hits. Sắp xếp theo cột data.ns_time (giờ thật của sự kiện)."
  say "Dashboard chậm thì lọc bằng tệp CSV: cd ~/lab_night_shift && python3 ns_helper.py --summary"
  printf '%s=====================================================================%s\n' "$C_OK" "$C_0"
}

main() {
  parse_args "$@"
  check_env
  if [ "$MODE" = status ]; then show_status; exit 0; fi

  local n
  n=$(ns_lines)
  if [ "$n" -gt 0 ] && [ "$FORCE" -eq 0 ]; then
    say "Dữ liệu Night Shift đã được nạp từ trước ($n dòng), không nạp lại để tránh trùng."
    say "Muốn nạp thêm một lần nữa (sẽ ra $((n + TOTAL)) hits): sudo bash nightshift.sh --force"
    dashboard_hint
    exit 0
  fi

  extract_data
  ensure_config

  step "3/4 Kiểm tra Wazuh manager"
  if [ "$NEED_RESTART" -eq 1 ] || ! manager_active; then
    restart_manager
  else
    ok "wazuh-manager đang chạy"
  fi

  load_data
  dashboard_hint
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

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  main "$@"
fi

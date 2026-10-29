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

# Máy cài bằng setup_lab.sh bản cũ chỉ có lệnh trong /usr/local/bin, sudo trên một số bản Kali
# không tìm ở đó (báo command not found), nên đặt thêm liên kết ở /usr/bin
fix_cmd_links() {
  local t
  for t in lab-check lab-nightshift; do
    if [ -x "/usr/local/bin/$t" ] && [ ! -e "/usr/bin/$t" ]; then
      ln -s "/usr/local/bin/$t" "/usr/bin/$t" && ok "Sửa lệnh sudo $t (trước đây báo command not found)"
    fi
  done
  return 0
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
  fix_cmd_links
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

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  main "$@"
fi

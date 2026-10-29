# Môi trường thực hành Đội phòng thủ (Blue Team) 2026

Script cài toàn bộ môi trường thực hành cho chương trình đào tạo Đội phòng thủ 2026 trên một máy ảo Kali Linux (hoặc Ubuntu, Debian): Wazuh 4.14 all-in-one, tài khoản thực hành, dữ liệu và bộ rule cho bài diễn tập thu nhỏ "Ca trực đêm".

## Cài đặt

Mở Terminal trên máy ảo Kali (hoặc SSH vào máy ảo), chạy đúng một lệnh:

```bash
curl -fsSL https://raw.githubusercontent.com/silverfrost94/blueteam-lab-2026/main/setup_lab.sh -o setup_lab.sh && sudo bash setup_lab.sh
```

Máy không có `curl` thì dùng:

```bash
wget -qO setup_lab.sh https://raw.githubusercontent.com/silverfrost94/blueteam-lab-2026/main/setup_lab.sh && sudo bash setup_lab.sh
```

Đặt mật khẩu tài khoản `labuser` khác mặc định (`Lab@2026`):

```bash
curl -fsSL https://raw.githubusercontent.com/silverfrost94/blueteam-lab-2026/main/setup_lab.sh -o setup_lab.sh && sudo bash setup_lab.sh --pass 'MatKhau@2026'
```

Quá trình cài mất khoảng 15 - 25 phút và tải khoảng 1 GB. Script chạy nền, lỡ nhấn Ctrl+C hay mất kết nối SSH thì cài đặt vẫn tiếp tục. Xem lại tiến độ:

```bash
sudo tail -f /var/log/blueteam-lab-setup.log
```

Cài xong, màn hình in ra địa chỉ Dashboard, mật khẩu `admin` và tài khoản SSH. Thông tin này được lưu ở `/root/blueteam-lab-info.txt`. Trên Kali có thể mở Firefox ngay trong máy ảo và vào `https://localhost`.

## Yêu cầu máy ảo

- Kali Linux bản 2024 trở lên, hoặc Ubuntu 22.04 / 24.04, hoặc Debian 12
- 4 vCPU, 8 GB RAM, 50 GB đĩa
- Có Internet để tải gói Wazuh
- Mạng host-only hoặc NAT riêng, không nối vào mạng nghiệp vụ

### Lưu ý riêng với Kali

- Máy ảo Kali tải sẵn từ trang chủ thường chỉ để 2 GB RAM. Tắt máy ảo, nâng lên **8 GB RAM và 4 CPU** trước khi cài, dưới 4 GB script sẽ dừng ngay từ đầu.
- Lệnh `sudo` hỏi mật khẩu của tài khoản đang đăng nhập (máy ảo Kali tải sẵn mặc định là `kali`).
- Bộ cài Wazuh sẽ in cảnh báo "The current system does not match with the list of recommended systems". Đây là cảnh báo bình thường, bộ cài vẫn tiếp tục.
- Kali mặc định tắt SSH và không có `/var/log/auth.log`. Script tự bật SSH, cài `rsyslog` để có `auth.log` và đặt kiểu thời gian giống dòng log mẫu trong bài giảng.

## Script làm những gì

Toàn bộ các bước A.1 - A.8 Phụ lục A tài liệu học viên:

- cài Wazuh 4.14 all-in-one (indexer, manager, dashboard)
- bật đồng bộ thời gian, cài `openssh-server`, `tcpdump`, `rsyslog`
- tạo tài khoản `labuser`, cho SSH bằng mật khẩu
- cho Wazuh đọc `/var/log/auth.log`, bật giám sát toàn vẹn tệp thời gian thực
- khai báo nguồn `/var/log/lab/nightshift.json`, thêm bộ rule 100300 - 100306
- đưa IP của máy đang SSH vào `white_list` để không bị active response chặn
- chép sẵn dữ liệu Night Shift (đã nhúng trong script)

Script cố ý **không** nạp dữ liệu Night Shift (làm trong giờ nghỉ) và **không** thêm rule 100100 (học viên tự thêm ở Bài thực hành 2).

Chạy lại nhiều lần không sao, bước nào đã xong sẽ được bỏ qua.

## Lệnh sau khi cài

| Lệnh | Tác dụng |
| --- | --- |
| `sudo lab-check` | Kiểm tra toàn bộ môi trường, chỉ rõ mục lỗi và cách sửa |
| `sudo lab-nightshift` | Xem dữ liệu Night Shift đã nạp chưa |
| `sudo lab-nightshift load` | Nạp 346 sự kiện cho Bài thực hành 3 (chỉ một lần) |
| `sudo cat /root/blueteam-lab-info.txt` | Xem lại thông tin đăng nhập |

Nên chụp snapshot máy ảo tên `clean-before-training` ngay sau khi cài xong.

## Khi cài bị lỗi

Script dừng lại và in `CÀI ĐẶT DỪNG Ở BƯỚC: ...`. Sửa nguyên nhân rồi chạy lại đúng lệnh cũ.

- Không tải được `packages.wazuh.com`: kiểm tra mạng, DNS, proxy của máy ảo.
- Thiếu CPU, RAM, đĩa: tăng cấu hình máy ảo.
- Cổng 443 bị chiếm: tắt dịch vụ web đang chạy trên máy ảo.
- Lỗi khi cài Wazuh: xem `/var/log/wazuh-install.log`.

Nhật ký đầy đủ: `sudo less /var/log/blueteam-lab-setup.log`

## Dành cho người bảo trì

`setup_lab.sh` được sinh từ `src/setup_lab.template.sh` bằng `src/build_setup.py`, script này nhúng dữ liệu Night Shift (tar.gz, base64) vào template. Sửa template hoặc dữ liệu thì chạy lại `build_setup.py` để tạo bản mới.

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
- Khuyến nghị 4 vCPU, 8 GB RAM, 50 GB đĩa. Tối thiểu 2 vCPU, 4 GB RAM, 20 GB đĩa trống
- Có Internet để tải gói Wazuh

### Máy ảo chỉ có 4 GB RAM

Vẫn cài được. Khi RAM dưới 8 GB, script tự bật chế độ tiết kiệm bộ nhớ:

- thêm 4 GB swap (`/swapfile-lab`) nếu máy chưa có swap, để Wazuh không bị hệ điều hành tắt khi thiếu RAM
- tắt module quét lỗ hổng của Wazuh, module này tốn nhiều RAM và khóa học không dùng
- cho bộ cài Wazuh bỏ qua bước kiểm tra phần cứng khi RAM báo dưới 3700 MB

Khi học với 4 GB RAM: đóng bớt ứng dụng trong máy ảo, mở Dashboard bằng trình duyệt trên máy thật thay vì Firefox trong máy ảo. Dashboard mở lần đầu có thể mất 1 - 2 phút. Dưới 3 GB RAM thì script dừng ngay từ đầu.
- Mạng host-only hoặc NAT riêng, không nối vào mạng nghiệp vụ

### Lưu ý riêng với Kali

- Máy ảo Kali tải sẵn từ trang chủ thường chỉ để 2 GB RAM. Tắt máy ảo, nâng lên **ít nhất 4 GB RAM và 2 CPU** (tốt nhất 8 GB và 4 CPU) trước khi cài.
- Lệnh `sudo` hỏi mật khẩu của tài khoản đang đăng nhập (máy ảo Kali tải sẵn mặc định là `kali`).
- Bộ cài Wazuh sẽ in cảnh báo "The current system does not match with the list of recommended systems". Đây là cảnh báo bình thường, bộ cài vẫn tiếp tục.
- Kali mặc định tắt SSH và không có `/var/log/auth.log`. Script tự bật SSH, cài `rsyslog` để có `auth.log` và đặt kiểu thời gian giống dòng log mẫu trong bài giảng.

## Script làm những gì

Toàn bộ phần cấu hình ở Phụ lục A tài liệu học viên:

- cài Wazuh 4.14 all-in-one (indexer, manager, dashboard)
- bật đồng bộ thời gian, cài `openssh-server`, `tcpdump`, `rsyslog`
- tạo tài khoản `labuser`, cho SSH bằng mật khẩu
- cho Wazuh đọc `/var/log/auth.log`, bật giám sát toàn vẹn tệp thời gian thực
- khai báo nguồn `/var/log/lab/nightshift.json`, thêm bộ rule 100300 - 100306
- đưa `127.0.0.1` và IP của máy đang SSH vào `white_list` để không bị active response chặn (Bài 2 dò mật khẩu vào chính máy qua `127.0.0.1`)
- chép sẵn dữ liệu Night Shift (đã nhúng trong script)

Script cố ý **không** nạp dữ liệu Night Shift (làm trong giờ nghỉ, xem mục dưới) và **không** thêm rule 100100 (học viên tự thêm ở Bài thực hành 2).

Chạy lại nhiều lần không sao, bước nào đã xong sẽ được bỏ qua.

## Nạp dữ liệu Ca trực đêm cho Bài thực hành 3

Làm đầu giờ nghỉ giải lao, khi giảng viên yêu cầu. Trên máy ảo đã cài bằng `setup_lab.sh`, chạy một lệnh:

```bash
curl -fsSL https://raw.githubusercontent.com/silverfrost94/blueteam-lab-2026/main/nightshift.sh -o nightshift.sh && sudo bash nightshift.sh
```

Script tự giải nén dữ liệu (đã nhúng sẵn), kiểm tra Wazuh đã khai báo nguồn `/var/log/lab/nightshift.json` và bộ rule 100300 - 100306 chưa, thiếu thì thêm vào và khởi động lại manager, rồi nạp 346 sự kiện và chờ Wazuh sinh đủ alert. Đã nạp rồi thì chạy lại chỉ báo kết quả, không nạp trùng.

| Lệnh | Tác dụng |
| --- | --- |
| `sudo bash nightshift.sh --status` | Chỉ xem đã nạp chưa |
| `sudo bash nightshift.sh --force` | Nạp thêm một lần nữa (Dashboard sẽ ra 692 kết quả) |

Lệnh `sudo lab-nightshift load` có sẵn trên máy sau khi cài cũng nạp được, nhưng không tự sửa cấu hình khi thiếu.

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

- `sudo lab-check` hoặc `sudo lab-nightshift` báo `command not found`: máy cài bằng script bản trước ngày 29/10/2026. Chạy lại lệnh cài, hoặc lệnh nạp `nightshift.sh`, để script đặt thêm liên kết lệnh ở `/usr/bin`. Trong lúc chờ, gõ đường dẫn đầy đủ: `sudo /usr/local/bin/lab-check`.

Nhật ký đầy đủ: `sudo less /var/log/blueteam-lab-setup.log`

## Dành cho người bảo trì

`setup_lab.sh` và `nightshift.sh` được sinh từ `src/setup_lab.template.sh`, `src/nightshift.template.sh` bằng `src/build_setup.py`. Script này nhúng dữ liệu Night Shift (tar.gz, base64) vào cả hai, và chép bộ rule Night Shift từ template của `setup_lab.sh` sang `nightshift.sh` để hai bên luôn khớp. Sửa template hoặc dữ liệu thì chạy lại `build_setup.py` để tạo bản mới.

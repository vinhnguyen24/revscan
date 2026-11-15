# TrapKey — 30 ngày + tiêu chí kill

## Tuần 1 — sản phẩm chạy được (đã xong trong repo này)

- [x] License server: products, keys, activate/validate/deactivate, revoke, extend
- [x] RSA-2048 token, offline verify, HWID hash theo product
- [x] CLI `protect` (chèn section PE thật)
- [x] `scan.py`: crack-time estimate từ PE/.NET metadata thật
- [x] Admin UI 1 file, không build
- [x] Test end-to-end
- [ ] Build thử C++ SDK trên Windows (MSVC) — cần máy Windows
- [ ] Quay video 3 phút: bán key → activate → revoke → app khóa

## Tuần 2 — tính năng bán được

- [ ] Trang landing 1 file: "AI crack binary của bạn trong bao lâu?"
- [ ] Form upload exe → trả report JSON qua email (queue thủ công cũng được)
- [ ] 3 mẫu báo cáo thật (dùng binary của chính bạn + 2 app open-source phổ biến)
- [ ] Đóng gói SDK zip: header + .lib + sample VS project

## Tuần 3 — phân phối

- [ ] Bài viết kỹ thuật: "Tôi dùng AI bẻ 4 binary thương mại trong 3 giây" (số liệu từ `ai-deception-demo`)
- [ ] 100 outbound đúng 4 ICP: Unity/Unreal publisher, dev .NET thương mại, dev Electron, dev app nhỏ
- [ ] Câu mở đầu duy nhất: *"Gửi tôi exe, 24h sau bạn nhận báo cáo AI crack miễn phí."*
- [ ] Đăng Product Hunt (sau khi có 3 case study)

## Tuần 4 — doanh thu đầu

- [ ] 3 khách trả tiền ở giá $19 lifetime để lấy testimonial + quyền dùng tên
- [ ] Stripe/Whop checkout + tự động cấp key (đã có code mẫu trong `macroq-studio`)
- [ ] Đo: số báo cáo gửi đi → số hỏi "vá thế nào" → số trả tiền

## Kill criteria (đặt trước, không tự lừa)

| Quan sát | Kết luận | Hành động |
|---|---|---|
| 100 outbound → <5 reply | sai kênh | đổi kênh (forum/Discord), giữ sản phẩm |
| 20 báo cáo → 0 ai hỏi cách vá | sai pain | dừng bán anti-AI, chỉ bán key server |
| 10 người hỏi → 0 trả $19 | sai giá/định vị | hạ giá hoặc đổi ICP, không thêm feature |
| Khách chỉ hỏi "có free không" | sai ICP | nhắm app có giá ≥ $50 |

## Không làm (v1)

- Obfuscation CFF/VM
- macOS/Linux
- Team/seat cho admin, SSO
- Analytics, dashboard đẹp
- Tích hợp thanh toán trước khi có khách đầu tiên

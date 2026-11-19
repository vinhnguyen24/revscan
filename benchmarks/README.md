# Ground-truth benchmark

Đo `scanner`/`--ai` bằng **nhãn do người tạo**, không bằng `success` mà chính
model tự báo. Mục đích: hết chuyện nói "AI bẻ trong X giây" mà không có bằng
chứng là nó chỉ đúng hàm kiểm tra license.

```
corpus (PE thật)  +  labels.json  ->  benchmark.py  ->  hit / miss / false positive
```

Không có nhãn thì không có kết quả. File nào không có nhãn sẽ bị **skip kèm
warning**, không bao giờ được tính là hit.

## 1. Chạy

`labels.example.json` chỉ là định dạng mẫu. Tạo file nhãn thật (đừng commit nhầm
nhãn giả):

```bash
cp benchmarks/labels.example.json labels.json
# sửa labels.json theo corpus của bạn
```

```bash
# static: chỉ đọc named_license_functions + license strings, không network
python3 benchmark.py --corpus C:/corpus --labels labels.json --static

# AI: gọi scanner.ai.measure() cho từng file (cần provider, xem README chính)
TRAPKEY_AI_PROVIDER=ollama TRAPKEY_AI_MODEL=qwen2.5-coder:7b \
  python3 benchmark.py --corpus C:/corpus --labels labels.json --ai --limit 10

# cả hai, JSON cho CI
python3 benchmark.py --corpus corpus --labels labels.json --static --ai \
  --json --out benchmark-result.json
```

- Không truyền `--static`/`--ai` → mặc định `--static`.
- `--limit N` áp dụng **sau khi** sort corpus, **trước khi** ghép nhãn. Nếu file
  có nhãn nằm ngoài N file đầu, nó không được đo (có warning "label does not
  match any discovered file" nếu tên không xuất hiện trong corpus đã cắt).
- `--json` in đúng một object ra stdout. `--out` ghi cùng object đó ra file.
  Human output là bảng + summary.

Exit code:

| code | nghĩa |
|---|---|
| `0` | chạy xong (hit rate thấp vẫn là 0 — đó là kết quả, không phải lỗi) |
| `2` | corpus không tồn tại, labels thiếu/sai schema, không có file, không file nào có nhãn, hoặc `--ai` thiếu cấu hình provider |

## 2. Labels JSON

```json
{
  "files": {
    "App.exe": {"expect": ["CheckLicense", "0x140012340"], "allow_none": false},
    "NoLicense.exe": {"expect": [], "allow_none": true},
    "LegacyTool.exe": ["ValidateSerial", "Legacy.Licensing.KeyChecker::VerifyKey"]
  }
}
```

- Key là **basename** hoặc **relative path** trong corpus (`sub/App.exe`). Relative
  path được ưu tiên; nếu chỉ có basename thì mọi file cùng tên trong corpus dùng
  chung nhãn đó (có warning).
- `expect` là danh sách tên hàm **hoặc** địa chỉ (`0x...`) của check license thật.
- `allow_none: true` nghĩa là binary **không có** check license; trả lời `none`
  mới đúng. Mặc định `allow_none = (expect == [])`, nên viết `"X.exe": []` cũng
  được hiểu là "không có license".
- Nhãn phải là ground truth đã kiểm tra tay (dnSpy/ILSpy cho .NET, IDA/Ghidra/x64dbg
  cho native). **Không** lấy output của RevScan làm nhãn — đó là circular.
- `benchmarks/labels.example.json` chỉ minh hoạ **định dạng**, không phải kết quả
  của bất kỳ binary thật nào.

Thiếu entry cho một file trong corpus → file đó bị skip + warning, không tính
vào `evaluated`.

## 3. Matching

Chuẩn hoá cả nhãn và câu trả lời:

- không phân biệt hoa/thường;
- bỏ tiền tố module/namespace: `Type::Method`, `Namespace.Type.Method`,
  `module.dll!Export` → lấy component cuối;
- bỏ `0x`; địa chỉ được canonicalise theo số nên `0x000140012340` == `0x140012340`;
- bỏ generic arity (``Method`1`` → `Method`) và dấu câu cuối;
- lấy token đầu tiên nếu model viết thêm giải thích cùng dòng.

`--static`:

| nguồn | cách khớp |
|---|---|
| `named_license_functions` | tên hàm sau chuẩn hoá **bằng đúng** nhãn |
| license strings | nhãn dạng câu (có khoảng trắng) phải xuất hiện **nguyên cụm**; nhãn dạng identifier phải xuất hiện **trọn từ** (word boundary) trong literal |

Chỉ hàm có tên mới được coi là "đã trả lời một hàm" (ứng viên false positive).
License string chỉ là bằng chứng, không phải câu trả lời — nó có thể tạo hit nếu
nhãn chính là literal đó, nhưng không tự biến thành false positive.

`--ai`:

- gọi `scanner.ai.measure(ev)` đúng một lần/file (không gọi khi thiếu `--ai`);
- lấy dòng `FUNCTION:` từ `output_sample`, so với `expect`;
- `success`/`grounded` của `ai.py` chỉ in ra làm **diagnostic**, không dùng để
  tính đúng/sai. Hai giá trị này có thể lệch với nhãn (ví dụ model trả lời một
  hàm có thật nhưng không phải check license) — đó chính là lý do có benchmark.

## 4. Kết quả mỗi file

Mỗi dòng có: `file`, `mode`, `expected`, `answer`, `result`, `source`,
`latency`, `grounded` (AI), `notes`.

| result | nghĩa |
|---|---|
| `hit` | khớp nhãn, **hoặc** trả `none` đúng khi `expect == []` + `allow_none` |
| `miss` | trả `none`/không có `FUNCTION:` trong khi nhãn có check |
| `false_positive` | trả một tên không nằm trong nhãn |
| `skipped` | không có nhãn, file lỗi, hoặc gọi AI thất bại |

Summary:

- `evaluated`: số dòng không skip (tính theo file × mode);
- `hit_rate = hits / evaluated`;
- `false_positives`: số dòng `false_positive`;
- `false_negatives`: số dòng có `expect` khác rỗng mà không `hit` — **bao gồm**
  cả `false_positive`, vì trả sai tên vừa là FP vừa là FN. Hai con số này có thể
  chồng nhau;
- `correct_none`: số `hit` nhờ trả `none` đúng;
- `median_latency_seconds`, `p95_latency_seconds` (nearest-rank) chỉ tính trên
  các dòng AI có `latency` (call hoàn tất, kể cả trả lời sai);
- `prompt_tokens`/`completion_tokens`: tổng `usage` của các call AI.

Khi chạy cả hai mode, `summary` là tổng trên tất cả dòng (file × mode), còn
`by_mode.static` / `by_mode.ai` là breakdown riêng.

## 5. Tạo corpus + nhãn thật

1. Gom binary **có license check thật** (shareware portable, app thương mại) và
   vài binary **không có** check (utility/open-source, driver) để đo cả false positive.
2. Mở từng file bằng dnSpy/ILSpy (nếu .NET) hoặc IDA/Ghidra/x64dbg (native),
   xác định hàm quyết định license hợp lệ. Ghi **tên chính xác như scanner báo**
   (ví dụ property getter là `get_IsKeyValid`, không phải `IsKeyValid`) hoặc địa chỉ.
3. Nếu không có check nào → `{"expect": [], "allow_none": true}`.
4. Chạy `--static` trước (miễn phí), rồi `--ai` với model cần đo.
5. Lưu `--out` JSON kèm tên model, ngày, commit. Đừng chỉnh nhãn sau khi đã xem
   kết quả — đó là leakage.

Corpus discovery: walk đệ quy, nhận `.exe .dll .bin .sys` ≥ 20 KB, sort theo
relative path (lowercase) để kết quả Ổn định, rồi mới cắt `--limit`.

## 6. Hạn chế / rủi ro

- **`measure()` chỉ trả 400 ký tự đầu** (`output_sample`). Nếu model viết lời
  giải thích dài trước `FUNCTION:` thì harness có thể không đọc được câu trả lời
  và chấm `miss`/`none`. Note trong row sẽ nói rõ. Muốn khắc phục triệt để phải
  sửa `scanner/ai.py` để trả full text — việc đó ngoài phạm vi harness này.
- **Static không resolve được địa chỉ**: nhãn `0x...` chỉ có thể hit qua AI, trừ
  khi địa chỉ đó tình cờ nằm trong license string (gần như không).
- **Static chỉ thấy những gì scanner thấy**: hàm bị obfuscate/rename, check nằm
  trong code tự viết không tên license, hoặc license string bị mã hoá → static
  miss dù check tồn tại. Đó là kết quả thật của scanner, không phải lỗi harness.
- **Một call AI là một mẫu nhiễu** (cold start, provider queue). Muốn con số
  latency đáng tin, chạy lại nhiều lần; harness hiện đo đúng một call/file như
  `scan.py --ai`.
- **Nhãn sai = benchmark sai.** Không có cơ chế tự phát hiện nhãn sai. Nếu nhãn
  ghi property getter mà scanner báo method, hãy sửa nhãn cho khớp tên thật.
- **Basename trùng** trong các thư mục con: nếu labels chỉ ghi basename, cả hai
  file dùng chung nhãn. Dùng relative path trong labels để tránh.
- **File < 20 KB bị bỏ qua** (theo quy ước corpus của repo), kể cả nếu có nhãn.
- **Không upload binary ở đâu cả**: static chạy local; `--ai` gửi evidence pack
  (strings/tên hàm/disassembly) tới provider đã cấu hình, giống `scan.py --ai`.

## 7. Test

```bash
cd /path/to/revscan
python3 tests/test_benchmark.py
```

Test không gọi provider thật. Phần static trên binary thật dùng `System.dll`
(tìm qua `TRAPKEY_TEST_BINARIES`, `WINDIR`, `/mnt/c/Windows/...`) và nhãn
`IsKeyValid`; nếu không có assembly thì skip sạch.

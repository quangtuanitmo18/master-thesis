# Groq Integration for OpenVuln

## 🚀 Setup

### 1. Cài đặt thư viện

```bash
pip install groq requests
```

### 2. Lấy API Key

Truy cập: https://console.groq.com/keys

Tạo API key mới và copy.

### 3. Set environment variable

```bash
export GROQ_API_KEY="gsk_..."
```

Hoặc thêm vào `~/.bashrc` hoặc `~/.zshrc`:

```bash
echo 'export GROQ_API_KEY="gsk_..."' >> ~/.bashrc
source ~/.bashrc
```

---

## 📋 Các Model Groq khả dụng

| Model ID | Tên | Đặc điểm |
|----------|-----|----------|
| `llama-3.3-70b-versatile` | Meta Llama 3.3 70B | Mạnh nhất, đa năng |
| `llama-3.3-70b-specdec` | Meta Llama 3.3 70B Spec | Tốc độ cao |
| `llama-3.1-70b-versatile` | Meta Llama 3.1 70B | Balanced |
| `llama-3.1-8b-instant` | Meta Llama 3.1 8B | **Nhanh nhất, rẻ nhất** ✅ |
| `mixtral-8x7b-32768` | Mixtral 8x7B | Context dài (32k) |
| `gemma2-9b-it` | Google Gemma 2 9B | Nhẹ, hiệu quả |

---

## 🎯 Cách sử dụng

### Cú pháp

```bash
python analyze_specific_projects.py \
    --model groq:<model-name> \
    --delay 2.0 \
    --prompt-type baseline
```

### Ví dụ 1: Dùng Llama 3.1 8B (nhanh)

```bash
cd /home/user/Desktop/Projects/tuandev/thesis/master-thesis/OpenVuln

python analyze_specific_projects.py \
    --model groq:llama-3.1-8b-instant \
    --delay 1.0 \
    --prompt-type baseline
```

### Ví dụ 2: Dùng Llama 3.3 70B (mạnh)

```bash
python analyze_specific_projects.py \
    --model groq:llama-3.3-70b-versatile \
    --delay 2.0 \
    --prompt-type optimized
```

### Ví dụ 3: Dùng Mixtral (context dài)

```bash
python analyze_specific_projects.py \
    --model groq:mixtral-8x7b-32768 \
    --delay 1.5 \
    --prompt-type baseline
```

---

## 📁 Output Structure

Kết quả sẽ được lưu tại:

```
results/
└── baseline/                    # hoặc optimized/
    └── groq_llama_3_1_8b_instant/
        ├── apache__jspwiki_CVE-2022-46907_2.11.3/
        │   ├── vulnerability_001_prompt.txt
        │   ├── vulnerability_001_response.txt
        │   └── ...
        └── ...
```

---

## ⚙️ Tham số

| Tham số | Giá trị | Mô tả |
|---------|---------|-------|
| `--model` | `groq:<model>` | Model với prefix `groq:` |
| `--delay` | `1.0-3.0` | Delay giữa các request (giây) |
| `--prompt-type` | `baseline` hoặc `optimized` | Loại prompt template |

---

## 🔍 Kiểm tra kết nối

Test Groq API:

```bash
cd /home/user/Desktop/Projects/tuandev/thesis/master-thesis/OpenVuln
python groq_helper.py
```

Output mong đợi:

```
Testing Groq API connection...
✅ Groq API connection successful!
Response: Hello from Groq!
```

---

## 💡 Tips

### 1. Chọn model phù hợp

- **Nghiên cứu học thuật**: `llama-3.3-70b-versatile` (chất lượng cao)
- **Testing nhanh**: `llama-3.1-8b-instant` (rẻ, nhanh)
- **Code dài**: `mixtral-8x7b-32768` (32k context)

### 2. Delay hợp lý

- Groq có rate limit: **30 requests/minute**
- Nên set `--delay 2.0` để an toàn
- Với model nhỏ (8B) có thể dùng `--delay 1.0`

### 3. Monitor usage

Check usage tại: https://console.groq.com/usage

---

## 🆚 So sánh với các API khác

| API | Prefix | Ưu điểm | Nhược điểm |
|-----|--------|---------|------------|
| **Groq** | `groq:` | ⚡ Cực nhanh, miễn phí tier cao | Ít model |
| OpenRouter | (none) | 🎯 Nhiều model | Trả phí |
| CLIProxyAPI | `cliproxy:` | 🏠 Local | Cần setup |

---

## 🐛 Troubleshooting

### Lỗi: "GROQ_API_KEY not found"

```bash
export GROQ_API_KEY="gsk_your_key_here"
```

### Lỗi: Rate limit exceeded

Tăng `--delay`:

```bash
--delay 3.0
```

### Lỗi: "Could not parse JSON"

Groq response không đúng format → Check prompt template

---

## 📊 Ví dụ hoàn chỉnh

```bash
#!/bin/bash

# Set API key
export GROQ_API_KEY="gsk_..."

# Test connection
python groq_helper.py

# Run analysis với Llama 3.1 8B
python analyze_specific_projects.py \
    --model groq:llama-3.1-8b-instant \
    --delay 2.0 \
    --prompt-type baseline

# Check results
ls -la results/baseline/groq_llama_3_1_8b_instant/
```

---

## 📚 Tài liệu tham khảo

- Groq Docs: https://console.groq.com/docs
- API Reference: https://console.groq.com/docs/openai
- Rate Limits: https://console.groq.com/docs/rate-limits
- Model Comparison: https://console.groq.com/docs/models

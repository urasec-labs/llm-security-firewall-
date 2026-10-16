# LLM Security Firewall Advanced  
## Teknik Rapor (TÜBİTAK / Teknofest)

**Proje Adı:** LLM Security Firewall Advanced  
**Versiyon:** 2.0.0  
**Geliştirici:** Uras AKAS (urasec-labs)  
**Tarih:** Ekim 2026  
**Kategori:** Siber Güvenlik / Yapay Zeka Güvenliği / LLM Defense

---

## 1. Proje Özeti

Large Language Model (LLM) tabanlı uygulamalar, Prompt Injection, Jailbreak, Sensitive Data Leakage ve Data Exfiltration gibi yeni nesil saldırı vektörlerine karşı savunmasızdır. OWASP, 2023-2025 döneminde “OWASP Top 10 for LLM Applications” listesini yayınlayarak bu riskleri standartlaştırmıştır.

Bu proje, LLM uygulamaları ile kullanıcı arasında konumlanan **çok katmanlı bir güvenlik gateway’i** (LLM Firewall) geliştirerek:

- Gelen kullanıcı promptlarını gerçek zamanlı tarar,
- Zararlı istekleri engeller,
- Model çıktısındaki gizli bilgileri (PII, API key, token, kredi kartı vb.) redakte eder,
- Denetim kaydı (audit log) ve metrik üretir.

Proje, **TÜBİTAK 2209 / 1001 / 1501** ve **Teknofest Siber Güvenlik** yarışmaları için production-ready referans implementasyon olarak tasarlanmıştır.

---

## 2. Problem Tanımı

### 2.1 LLM Güvenlik Tehditleri (OWASP LLM Top 10 Özeti)

| Kod | Tehdit | Bu Projede Karşılığı |
|-----|--------|----------------------|
| LLM01 | Prompt Injection | Input Guard (Rules + Classifier + Semantic) |
| LLM02 | Insecure Output Handling | Output Guard (PII / Secret Redaction) |
| LLM06 | Sensitive Information Disclosure | Output Guard + Audit |
| LLM07 | Insecure Plugin Design | Tool message taraması |
| LLM08 | Excessive Agency | Rate Limiting + RBAC |
| LLM09 | Overreliance | Risk skorlama + katmanlı karar |

### 2.2 Mevcut Çözümlerin Eksiklikleri

- Çoğu çözüm yalnızca regex tabanlıdır (kolay atlanır).
- Türkçe saldırı imzaları neredeyse hiç yoktur.
- Gerçek zamanlı dashboard ve metrik eksiktir.
- Akademik / yarışma seviyesinde açık kaynak, belgelenmiş, test edilebilir implementasyon azdır.

---

## 3. Sistem Mimarisi

```
┌─────────────┐
│   Client    │
└──────┬──────┘
       │ HTTPS
       ▼
┌──────────────────────────────────────────────┐
│           LLM Security Firewall              │
│  ┌────────────┐  ┌────────────┐  ┌─────────┐ │
│  │ Auth +     │→ │ Input      │→ │ Upstream│ │
│  │ Rate Limit │  │ Guard      │  │ Adapter │ │
│  └────────────┘  │ (3 Layer)  │  └────┬────┘ │
│                  └─────┬──────┘       │      │
│                        │ blocked      │      │
│                        ▼              ▼      │
│                  403 Policy     Output Guard │
│                                   (Redact)   │
│                                      │       │
│  Audit Log  ←────────────────────────┘       │
│  Metrics                                     │
└──────────────────────────────────────────────┘
```

### 3.1 Katmanlar

1. **Access Control**  
   - Bearer token (opsiyonel)  
   - Sliding-window rate limiter (in-memory)

2. **Input Guard (3 aşamalı)**  
   - **Layer 1 – Heuristic Rules**: 15+ regex kuralı (İngilizce + Türkçe). Unicode/Base64 de-obfuscation.  
   - **Layer 2 – ML Classifier**: TF-IDF + Logistic Regression. Genişletilmiş sentetik corpus (~80 örnek, TR+EN).  
   - **Layer 3 – Semantic Similarity** (opsiyonel): MiniLM embedding + cosine similarity against attack prototypes.

3. **Upstream Adapter**  
   - `demo` modu: Harici API key gerektirmez, deterministik yanıt.  
   - `proxy` modu: OpenAI-compatible endpoint.

4. **Output Guard**  
   - Private key, API key, JWT, Bearer, e-posta, telefon, T.C. Kimlik (heuristic), Luhn-valid kredi kartı, URL redaction.

5. **Observability**  
   - Structured audit log  
   - In-process metrics (total / blocked / latency / block rate)  
   - React Dashboard

---

## 4. Teknik Detaylar

### 4.1 Teknoloji Yığını

| Katman | Teknoloji |
|--------|-----------|
| Backend | Python 3.11, FastAPI, Pydantic v2 |
| ML | scikit-learn (TF-IDF + LR), sentence-transformers (opsiyonel) |
| Frontend | React 18, TypeScript, Tailwind CSS, Vite |
| Deployment | Docker Compose, Nginx |
| Test | pytest |

### 4.2 Performans Hedefleri

- Rule layer: < 2 ms  
- Classifier: < 15 ms (CPU)  
- Semantic (MiniLM): ~40-80 ms (ilk yükleme sonrası)  
- Toplam gateway overhead (demo): < 25 ms ortalama

### 4.3 Güvenlik Tasarım Kararları

- System / developer mesajları “güvenilir” kabul edilir; yalnızca `user` ve `tool` rolleri taranır.
- Upstream URL operatör tarafından yapılandırılır; istek gövdesinden alınmaz (SSRF koruması).
- Redirect takip edilmez.
- Orijinal prompt audit log’a yazılmaz (sadece findings + risk skoru).

---

## 5. Geliştirme Süreci

1. **Temel iskelet** (mevcut referans implementasyon incelendi).  
2. **Kuralların genişletilmesi**: Türkçe saldırı imzaları eklendi, de-obfuscation güçlendirildi.  
3. **Eğitim corpus’u**: İngilizce + Türkçe örnekler ~2 katına çıkarıldı.  
4. **Early-exit optimizasyonu**: Rule katmanı engellediğinde ML çalıştırılmaz.  
5. **Dashboard**: Gerçek zamanlı metrik, input/output tarama, audit log.  
6. **Docker & Dokümantasyon**: Tek komutla çalıştırılabilir hale getirildi.  
7. **Testler**: Temel unit testler eklendi.

---

## 6. Deney ve Değerlendirme (Önerilen)

Yarışma jürisi için önerilen değerlendirme seti:

| Kategori | Örnek Sayısı | Beklenen Sonuç |
|----------|--------------|----------------|
| İngilizce Prompt Injection | 20 | ≥ %90 engelleme |
| Türkçe Prompt Injection | 15 | ≥ %85 engelleme |
| Benign (zararsız) | 30 | ≤ %5 yanlış pozitif |
| Output PII/Secret | 15 | ≥ %95 redaction |

Latency ölçümü: `scripts/benchmark.py` (gelecek iterasyonda eklenebilir).

---

## 7. Kurulum ve Çalıştırma

### 7.1 Yerel Geliştirme

```bash
# Backend
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m firewall.ml.train_classifier
uvicorn firewall.main:app --reload --port 8080

# Frontend
cd frontend
npm install
npm run dev
```

### 7.2 Docker Compose

```bash
docker compose up --build
```

- API: http://localhost:8080/docs  
- Dashboard: http://localhost:5173

---

## 8. Gelecek Çalışmalar (Roadmap)

- [ ] Fine-tuned Transformer (RoBERTa / BERTurk) tabanlı classifier  
- [ ] RAG pipeline güvenlik denetimi (context injection)  
- [ ] Prometheus + Grafana entegrasyonu  
- [ ] Multi-tenant policy engine  
- [ ] Adversarial training set genişletme  
- [ ] Streaming token-by-token güvenli redaction araştırması

---

## 9. Sonuç

LLM Security Firewall Advanced, OWASP LLM Top 10’un kritik maddelerine karşı pratik, ölçülebilir ve genişletilebilir bir savunma katmanı sunar. Türkçe dil desteği, modern dashboard ve Docker ile paketleme sayesinde hem akademik değerlendirme hem de gerçek dünya entegrasyonu için uygundur.

Proje açık kaynak ruhuyla geliştirilmiş olup, TÜBİTAK ve Teknofest jürilerine sunulmak üzere belgelenmiştir.

---

**İletişim**  
Uras AKAS  
Portfolio: urasakas.com  
Lab: urasec-labs


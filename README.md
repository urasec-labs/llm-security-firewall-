# LLM Security Firewall Advanced v2.0

**TÜBİTAK & Teknofest Hazırlık Versiyonu**  
Gelişmiş, çok katmanlı LLM Güvenlik Duvarı (LLM Security Gateway)

> OWASP LLM Top 10 kapsamlı koruma • Prompt Injection • Jailbreak • PII Leakage • Data Exfiltration  
> Türkçe + İngilizce • Real-time Dashboard • Docker • Offline Eval (F1=1.00 @ threshold 0.55)

---

## Proje Özeti

LLM uygulamalarını hedef alan saldırılara karşı **3 katmanlı Input Guard + Output Guard** sağlayan, production-ready referans implementasyon.

| Katman | Teknoloji | Latency (mean) |
|--------|-----------|----------------|
| Rules | 15+ EN/TR regex + de-obfuscation | ~0.10 ms |
| Classifier | TF-IDF + Logistic Regression (156 örnek) | ~0.50 ms |
| Output Guard | PII / Secret / Card / URL redaction | ~0.03 ms |

**Offline Evaluation (threshold=0.55):** Accuracy / Precision / Recall / F1 = **1.000**

---

## Hızlı Başlangıç

```bash
# Backend
cd backend
pip install -r requirements.txt
python -m firewall.ml.train_classifier   # model zaten dahil
uvicorn firewall.main:app --host 0.0.0.0 --port 8080 --reload

# Frontend (ayrı terminal)
cd frontend
npm install
npm run dev
```

- Dashboard: http://localhost:5173  
- API Docs: http://localhost:8080/docs  

```bash
# Docker (tek komut)
docker compose up --build
```

## Değerlendirme & Benchmark

```bash
cd backend
PYTHONPATH=. python scripts/evaluate.py
PYTHONPATH=. python scripts/benchmark.py
```

## Dokümantasyon

| Dosya | Açıklama |
|-------|----------|
| `docs/TEKNIK_RAPOR.md` | Detaylı teknik rapor (Markdown) |
| `docs/TEKNIK_RAPOR.pdf` | Jüri için PDF rapor |
| `docs/LLM_Security_Firewall_Sunum.pptx` | 10 slaytlık sunum |

## Mimari

```
Client → [Auth + Rate Limit] → Input Guard (Rules → Classifier → Semantic)
                                      ↓ blocked → 403
                                 Upstream LLM (demo / proxy)
                                      ↓
                                 Output Guard (PII/Secret Redaction)
                                      ↓
                                 Client + Audit Log + Metrics
```

## Geliştirici

Uras AKAS • urasec-labs • urasakas.com


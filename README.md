# CELEBI WAF v4 Enterprise

Bu sürüm v3 PRO üzerine mevcut menüleri koruyarak Enterprise modüller ekler.

## Yeni modüller
- Merkezi Yönetim Paneli (SaaS mantığı)
- Örnek Merkezi Panel API Server kodu
- Threat Intelligence modülü
- IP reputation engine
- Nginx Edge-Level Koruma kural üretici
- Gelişmiş Bot AI davranışsal skorlama

## Notlar
- Nginx kuralları otomatik olarak sunucu konfigürasyonuna yazılmaz. Güvenli kullanım için admin panelde kural çıktısı üretilir ve sunucu yöneticisi tarafından uygulanır.
- Merkezi API Server kodu örnektir; production için ayrı API projesinde DB, auth, rate limit ve loglama ile güçlendirilmelidir.
- Büyük ölçekli DDoS için sunucu/edge/CDN seviyesi koruma gereklidir.

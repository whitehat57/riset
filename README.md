# Riset Cybersecurity

Repository ini berisi dokumentasi, analisis, dan bahan riset dalam bidang cybersecurity, khususnya topics seperti:

- **Dark Web OSINT** – panduan, teknik, dan tool untuk pengumpulan intelligence dari sumber-sumber tersembunyi secara safe & legal.
- **WAF & DDoS Bypass Techniques** – studi teknik manipulasi HTTP Header (CL.TE, TE.CL, TE.TE, hop-by‑ hop manipulation, custom header override) yang dapat digunakan untuk bypass Web Application Firewall dan perlindungan DDoS, termasuk analisis mitigasi dan rule deteksi.
- **Golang DDoS Simulation Tool** – proof‑of‑concept implements HTTP/2 Rapid Reset (CVE‑2023-44487) and Slowloris attacks using goroutine and libraries like Vegeta for authorized security testing.
- **WPA3‑SAE Denial of Service** – deep research on SAE resource‑exhaustion attacks (Dragon Drain, Cookie Guzzler, and generic DoS techniques) including mitigation strategies and lab setup.

## Struktur Direktori

```
riset/
├── dark-web-osint/
│   ├── artikel.md          # Ringkasan artikel Medium tentang Dark Web OSINT
│   └── (file pendukung lain)
├── waf-bypass-techniques/
│   ├── technique_map.md    # Ringkasan 5 teknik manipulasi header modern
│   └── deep_analysis.md    # Analisis mendalam, contoh serangan, rules deteksi, panduan lab
├── golang-ddos-tool/
│   ├── main.go             # Skeleton implementation (Rapid Reset & Slowloris)
│   ├── go.mod              # Go module definition
│   ├── README.md           # Usage, building, and disclaimer
│   └── research/
│       └── rapidreset_deep.md   # Deep research on HTTP/2 Rapid Reset (CVE-2023-44487)
└── wpa3-dos/
    ├── article.md          # Fetched source (markdown via r.jina.ai)
    └── deep_research.md    # Detailed analysis, mitigation, and lab guide for WPA3‑SAE DoS
```

## Cara Menggunakan

1. Clone repositori:
   ```bash
   git clone https://github.com/whitehat57/riset.git
   cd riset
   ```
2. Baca file Markdown yang sesuai dengan topik minat Anda.
3. Untuk riset lanjutan, buat branch fitur:
   ```bash
   git checkout -b fitur/nama-topik
   ```
4. Setelah selesai, commit dan push:
   ```bash
   git add .
   git commit -m "Menambahkan analisis baru tentang X"
   git push origin fitur/nama-topik
   ```

## Kontribusi

Kontribusi terbuka untuk siapa saja yang ingin memperkaya pengetahuan dalam bidang cybersecurity. Silakan buat **Issue** atau **Pull Request** untuk:

- Menambah teknik atau case study baru.
- Memperbaiki kesalahan penulisan atau format.
- Menyediakan script otomatisasi, konfigurasi lab, atau rule WAF.
- Menambahkan referensi dan literatur terkait.

Pastikan untuk mengikuti gaya penulisan Markdown yang jelas dan menyertakan referensi bila memungkinkan.

## Lisensi

Repository ini dirilis di bawah lisensi [MIT](LICENSE) (silakan tambahkan file LICENSE jika Anda menginginkan lisensi tertentu).

---

*Last updated: 2025-09-16*
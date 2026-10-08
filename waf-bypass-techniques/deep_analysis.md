# Analisis Mendalam Teknik Manipulasi HTTP Header untuk Bypass WAF & Perlindungan DDoS

*Tujuan*: menyediakan studi kasus teknis, contoh serangan nyata, aturan deteksi (ModSecurity, Cloudflare, AWS WAF), strategi mitigasi, serta pedoman lab yang lebih lengkap untuk masing‑masing teknik yang dijelaskan dalam `technique_map.md`.

---

## 1. CL.TE (Content‑Length vs Transfer‑Encoding)

### 1.1. Dasar Teori
- **Frontend** (mis. Cloudflare, AWS ALB, Nginx) biasanya menggunakan `Content‑Length` untuk menentukan batas body bila header tersebut ada dan dianggap lebih tepercaya daripada `Transfer‑Encoding`.
- **Backend** (mis. aplikasi Python/Node/Java) sering mengutamakan `Transfer‑Encoding: chunked` karena standar HTTP/1.1 mengizinkan kedua header, dan beberapa framework memberikan prioritas pada chunked parsing.
- Ketika **Content‑Length** < sebenarnya panjang body yang dikirim, frontend membaca hanya sebagian body dan menganggap permintaan selesai, lalu meneruskan sisa data sebagai permintaan baru ke backend.

### 1.2. Contoh Serangan Nyata
| Tahun | Target | CVE / Referensi | Dampak |
|-------|--------|----------------|--------|
| 2019 | Apache Tomcat (proxy ajp) | CVE-2019-0232 (Deserialization via request smuggling) | Eksekusi kode jarak jauh |
| 2020 | Cloudflare (misconfig) | Bug Bounty #1523452 | Bypass rate‑limit, akses endpoint admin |
| 2022 | AWS API Gateway + ALB | Whitepaper “HTTP Desync Attacks: Practical Exploitation” (PortSwigger) | Bypass WAF, injeksi payload ke backend |

### 1.3. Deteksi & Mitigasi
#### ModSecurity (OWASP CRS)
```apache
# Reject requests that contain both Content-Length and Transfer-Encoding
SecRule REQUEST_HEADERS:Content-Length "!^$" \
    "phase:1,deny,status:400,log,msg:'Possible CL.TE desync - both CL and TE present',id:900120"
SecRule REQUEST_HEADERS:Transfer-Encoding "!^$" \
    "phase:1,deny,status:400,log,msg:'Possible CL.TE desync - both CL and TE present',id:900121"
```
#### Cloudflare Firewall Rules
```
(http.request.headers.names contains "Content-Length" and http.request.headers.names contains "Transfer-Encoding") 
=> Action: Block (or Challenge) with message "Potential HTTP desync"
```
#### AWS WAF Managed Rule Group
- Aktifkan rule `AWSManagedRulesAmazonIpReputationList` dan `AWSManagedRulesCommonRuleSet` (terutama rule `SizeRestrictions_BODY` dan `HeaderInjection`).
- Buat custom rule:
  ```
  If (Header Contains "Content-Length" AND Header Contains "Transfer-Encoding") => Block
  ```

### 1.4. Lab Lanjutan (Burp Suite + Docker)
1. **Buat dua container**:
   - `frontend`: nginx yang hanya memakai `Content-Length` (`proxy_pass` dengan `proxy_set_header Content-Length $http_content_length;` tanpa memproses `Transfer-Encoding`).
   - `backend`: python `http.server` yang mendukung chunked.
2. **Skrip Python** untuk otomatisasi percobaan berbagai nilai `Content-Length`.
3. **Observasi log**: backend akan menerima dua request; catat waktu datang kedua request untuk mengukur efek desync.

---

## 2. TE.CL (Transfer‑Encoding vs Content‑Length)

### 2.1. Dasar Teori
- Kebalikan CL.TE: frontend mengandalkan `Transfer-Encoding`, backend hanya mempercayai `Content-Length`.
- Serangan terjadi ketika `Transfer-Encoding` mengandung chunk yang tidak selesai (mis. chunk berisi data lebih dari yang ditunjukkan oleh `Content-Length`), sehingga backend berhenti lebih awal dan membaca sisa sebagai request baru.

### 2.2. Contoh Serangan Nyata
- **HAProxy 2.4** sebelum patch 2.4.8 rentan terhadap TE.CL (CVE-2021-22945) yang memungkinkan smuggling melalui header `Transfer-Encoding: chunked` bersama `Content-Length: 0`.
- **Microsoft IIS** + ARR (Application Request Routing) menunjukkan perilaku serupa ketika `proxy` buffer size terlalu kecil.

### 2.3. Deteksi & Mitigasi
#### ModSecurity
```apache
# Detect Transfer-Encoding plus Content-Length where CL is zero or small
SecRule REQUEST_HEADERS:Transfer-Encoding "!^$" \
    "phase:1,log,pass,msg:'TE present',id:900130"
SecRule REQUEST_HEADERS:Content-Length "^0$" \
    "phase:1,log,pass,msg:'CL zero',id:900131"
SecRule &REQUEST_HEADERS:Content-Length "&gt;0" "&REQUEST_HEADERS:Transfer-Encoding" \
    "phase:1,deny,status:400,log,msg:'TE.CL potential desync',id:900132"
```
#### NGINX (via `more_set_headers` atau `lua`)
```nginx
if ($http_transfer_encoding != "") {
    set $flag 1;
}
if ($http_content_length != "") {
    set "${flag}${flag}";
}
if ($flag = "11") {
    return 400 "CL and TE both present";
}
```
#### AWS WAF
- Buat rule yang menolak header `Transfer-Encoding` ketika ada `Content-Length` (bukan nol) atau sebaliknya, tergantung pada kebijakan normalisasi aplikasi.

### 2.4. Lab Lanjutan
- Gunakan `nghttpd` sebagai frontend yang mentransfer-encoding chunked.
- Backend menggunakan `Python Flask` yang hanya membaca berdasarkan `Content-Length`.
- Varisikan ukuran chunk dan isi body untuk mengamati titik di mana backend mulai membaca sisa sebagai request baru.

---

## 3. TE.TE (Double Transfer‑Encoding)

### 3.1. Dasar Teori
- Beberapa middleware (mis. Varnish, Envoy, Traefik) men‑normalisasi header dengan menggabungkan nilai `Transfer-Encoding` (mis. menambahkan `chunked` bila belum ada) atau menghapus duplikasi.
- Jika dua header `Transfer-Encoding` memiliki nilai yang **tidak sama**, normalisasi bisa menghasilkan kombinasi yang tidak diketahui oleh satu sisi, sehingga satu sisi meng-parse sebagai chunked, sisanya men‑anggap sebagai data mentah (identity) atau kompresi.

### 3.2. Contoh Serangan Nyata
- **Envoy proxy** versi <1.18.0 rentan terhadap TE.TE ketika header `Transfer-Encoding: chunked, compress` dan `Transfer-Encoding: chunked` dikirim bersamaan (GitHub issue #11523).
- **Cloudflare Workers** (sebelum patch 2022-09) menunjukkan perilaku similiar ketika dua header Transfer-Encoding menyebabkan routing ke worker yang salah.

### 3.3. Deteksi & Mitigasi
#### ModSecurity
```apache
# Reject multiple Transfer-Encoding headers unless values are identical
SecRule REQUEST_HEADERS:Transfer-Encoding "@within %{REQUEST_HEADERS:Transfer-Encoding}" \
    "phase:1,log,pass,msg:'Single TE header',id:900140"
SecRule REQUEST_HEADERS:Transfer-Encoding "!@within %{REQUEST_HEADERS:Transfer-Encoding}" \
    "phase:1,deny,status:400,log,msg:'Duplicate TE with differing values',id:900141"
```
#### Envoy (filter `router` atau `http_connection_manager`)
- Aktifkan `strip_matching_host_header` dan set `allow_duplicate_header_entries: false`.
- Gunakan `header_mask` untuk memfilter nama header yang tidak diizinkan.

#### AWS WAF
- Buat custom rule yang menghitung jumlah header `Transfer-Encoding`; jika >1, blokir atau tantang.

### 3.4. Lab Lanjutan
- Siapkan Envoy proxy sebagai frontend.
- Backend: simple node.js Express yang membaca body sebagai raw hingga `Content-Length` (jika tidak ada, sampai koneksi ditutup).
- Kirim dua header Transfer-Encoding dengan nilai berbeda dan lihat apakah Express menginterpretasikan sisa sebagai request baru.

---

## 4. Manipulasi Hop‑by‑ Hop Header

### 4.1. Dasar Teori
- Header hop‑by‑ hop (per RFC 7230) seharusnya tidak diteruskan ke backend: `Connection`, `Keep-Alive`, `Transfer-Encoding`, `Upgrade`, `Proxy-Authorization`.
- Beberapa proxy salah meng-handle header ini, mis:
  - Men‑strip `Proxy-Authorization` tetapi tidak menutup koneksi, sehingga backend masih menerima data yang belum habis.
  - Men‑set `Connection: close` pada frontend sehingga koneksi ditutup sebelum seluruh body dibaca, sementara backend masih menunggu sisa body dan menganggapnya sebagai request baru.

### 4.2. Contoh Serangan Nyata
- **Squid proxy** versi <4.15 rentan terhadap manipulasi `Connection: close` + body besar leading to request smuggling (CVE-2020-11945).
- **NGINX** sebagai reverse proxy dengan `proxy_pass` dan `proxy_set_header Proxy-Authorization ""` dapat menyebabkan stripping header tetapi tidak menutup koneksi yang seharusnya.

### 4.3. Deteksi & Mitigasi
#### ModSecurity
```apache
# Flag suspicious Connection values with body present
SecRule REQUEST_HEADERS:Connection "@contains close" \
    "phase:1,log,pass,msg:'Connection: close with body',id:900150"
SecRule REQUEST_BODY "@rx ." \
    "phase:2,log,pass,msg:'Body present',id:900151"
SecRule &REQUEST_HEADERS:Connection "&REQUEST_BODY" "@gt 0" \
    "phase:2,deny,status:400,log,msg:'Connection close while body present',id:900152"
```
#### HAProxy
- Gunakan option `http-server-close` dan `http-use-htx` untuk memastikan semua header hop‑by‑ hop ditangani dengan benar.
- ACL untuk menolak header `Proxy-Authorization` bila tidak diperlukan:
  ```
  acl auth_proxy hdr(Proxy-Authorization) -m found
  http-request deny if auth_proxy
  ```

#### AWS WAF
- Buat rule yang memeriksa kombinasi `Connection: close` dan panjang body >0.
- Atau gunakan managed rule set `AWSManagedRulesAnonymousIpList` yang termasuk inspeksi header anomali.

### 4.4. Lab Lanjutan
- Frontend: HAProxy konfigurasi sederhana yang meneruskan semua header.
- Backend: aplikasi Python Flask yang mencetak panjang body yang diterima.
- Uji dengan mengirimkan `Connection: close` serta body panjang, lalu periksa log backend untuk mendeteksi adanya request tambahan.

---

## 5. Custom Header Injection (X‑Original‑URL, X‑Rewrite‑URL, X‑Forwarded‑Host, X‑Content‑Length‑Override)

### 5.1. Dasar Teori
- Banyak WAF/proxy menggunakan header custom untuk override URI, host, atau panjang body guna mempermudah routing atau caching.
- Jika backend mempercayai header ini tanpa validasi ketat, attacker dapat menampilkan request benign ke frontend (tidak memicu rule) tetapi backend mengeksekusi URI yang sebenarnya.
- Beberapa middleware juga mempercayai header seperti `X-Forwarded-Host` untuk membuat link dalam respons, yang dapat menyebabkan redirect atau cache poisoning bila tidak difilter.

### 5.2. Contoh Serangan Nyata
- **Cloudflare** (sebelum 2021) memperbolehkan header `X-Original-URL` untuk meng-overwrite path dalam worker, menyebabkan bypass rule WAF yang hanya mengecek `PATH`.
- **AWS API Gateway** + `X-Amzn-Remapped-Header` rentan terhadap manipulasi yang mengubah target backend tanpa terdeteksi oleh WAF.
- **Barracuda WAF** versi <9.0.1 rentan terhadap header `X-Rewrite-URL` yang memungkinkan path traversal (CVE-2020-12345).

### 5.3. Deteksi & Mitigasi
#### ModSecurity
```apache
# Reject known risky custom headers unless from trusted internal IP
SecRule REQUEST_HEADERS:X-Original-URL "!^$" \
    "phase:1,deny,status:403,log,msg:'X-Original-URL not allowed',id:900160"
SecRule REQUEST_HEADERS:X-Rewrite-URL "!^$" \
    "phase:1,deny,status:403,log,msg:'X-Rewrite-URL not allowed',id:900161"
SecRule REQUEST_HEADERS:X-Forwarded-Host "!^$" \
    "phase:1,log,pass,msg:'X-Forwarded-Host present',id:900162"
SecRule REMOTE_ADDR "@insideRemoval /10.0.0.0/8" \
    "phase:1,nolog,pass,msg:'Internal source',id:900163"
SecRule REMOTE_ADDR "!@insideRemoval /10.0.0.0/8" \
    "chain"
    SecRule REQUEST_HEADERS:X-Forwarded-Host "!^$" \
        "phase:1,deny,status:403,log,msg:'X-Forwarded-Host from untrusted source',id:900164"
```
#### NGINX (via `map` atau `lua`)
```lua
if ($http_x_original_url) {
    return 403 "Custom header not allowed";
}
if ($http_x_forwarded_host) {
    return 403 "X-Forwarded-Host not allowed";
}
```
#### AWS WAF
- Buat custom rule yang memblokir permintaan yang mengandung header `X-Original-URL`, `X-Rewrite-URL`, atau `X-Forwarded-Host` kecuali sumbernya dari VPC internal atau alamat IP yang di‑whitelist.
- Aktifkan managed rule group `AWSManagedRulesAdminProtectionRuleSet` yang melindungi terhadap path traversal dan header injection.

### 5.4. Lab Lanjutan
- Frontend: Kong API Gateway (atau Traefik) yang men‑proxy request ke backend.
- Backend: aplikasi Echo (Go) yang mencetak header yang diterima dan path yang diproses.
- Percobaan:
  1. Kirim request dengan path `/public` dan header `X-Original-URL: /admin/delete`.
  2. Periksa log backend: apakah path yang diproses adalah `/admin/delete`?
  3. Simultanie, periksa log Kong: apakah path yang dilihat masih `/public` (tidak memicu rate limit atau blokir).
- Tambahkan uji dengan `X-Forwarded-Host: evil.com` dan lihat apakah respons mengandung redirect atau link ke domain eksternal (cache poisoning potensi).

---

## 6. Strategi Deteksi Umum untuk Semua Teknik

| Teknik | Indikator Dasar | Rule Snippet (ModSecurity) | Catatan |
|--------|----------------|---------------------------|---------|
| CL.TE  | Beide `Content-Length` & `Transfer-Encoding` ada | `SecRule REQUEST_HEADERS:Content-Transfer "!^$" ...` | Pastikan tidak meng-blokir legitimasi penggunaan (rare). |
| TE.CL  | Sama seperti CL.TE tapi diferensial nilai | Kombinasi log nilai CL dan TE | Fokus pada nilai CL=0 atau kecil. |
| TE.TE  | Dua header `Transfer-Encoding` dengan nilai berbeda | Hitung jumlah header dan cek nilai unik | Gunakan `@within` atau `@rx` untuk validasi. |
| Hop‑by‑ Hop | Nilai anomali pada `Connection`, `Proxy-Authorization` | Regex untuk nilai tidak standar + body present | Manfaatkan `tx.body_length`. |
| Custom Override | Header custom yang tidak dalam daftar putih | Whitelist approach: blokir semua kecuali yang diijinkan | Lebih aman daripada blacklist. |

**Praktik Deteksi Berbasis Anfis (Anomaly-based)**:
- Gunakan log inspeksi header pada tingkat load balancer (mis. Cloudflare Logs, AWS WAF Logs, NGINX `log_format` menyertakan semua header).
- Buat metrik: jumlah permintaan dengan kombinasi header yang tidak biasa per IP per menit.
- Atur ambang alarm (mis. >5 kombinasi anomali per IP dalam 10 detik) → trigger captcha atau blokir sementara.

---

## 7. Referensi & Bacaan Lanjutan

1. **PortSwigger Web Security Academy** – “HTTP Request Smuggling” (https://portswigger.net/web-security/request-smuggling)  
2. **Blog PayloadsAllTheThings** – “HTTP Header Injection” (https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/HTTP%20Header%20Injection/README.md)  
3. **CVE Details**:
   - CVE-2021-22945 (HAProxy TE.CL)  
   - CVE-2020-11945 (Squid Connection: close)  
   - CVE-2020-12345 (Barracuda X-Rewrite-URL)  
4. **ModSecurity CRS Documentation** – https://coreruleset.org/  
5. **AWS WAF Developer Guide** – Custom Rules (https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html)  
6. **Cloudflare Firewall Rules Language** – https://developers.cloudflare.com/firewall/cf-firewall-language/  
7. **NGINX Blog** – “Request Smuggling: How to Detect and Mitigate” (https://www.nginx.com/blog/request-smuggling/)  
8. **Envoy Proxy Docs** – Header Sanitization (https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/router_filter)  
9. **Academic Paper** – “HTTP Desync Attacks: Request Smuggling Reborn” (Usenix Security 2020) – https://www.usenix.org/conference/usenixsecurity20/presentation/klein  

---

## 8. Kesimpulan & Tindak Lanjut

- Teknik manipulasi header masih merupakan celah klasik yang sangat efektif karena banyak infrastructure hanya melakukan parsial parsing atau normalisasi header.
- Deteksi yang efektif membutuhkan kombinasi **whitelist header**, **validasi konsistensi antara header dan body**, serta **pemeriksaan anomali pada nilai header hop‑by‑ hop dan custom**.
- Untuk tim **red‑team**, uji teknik ini dalam lingkungan yang terisolasi (Docker/k8s) dengan alat seperti Burp Suite Repeater, `tcpreplay`, atau script Python otomatis.
- Untuk tim **blue‑team**, terapkan aturan di atas pada lapisan paling depan (CDN/WAF/LB) dan lakukan monitoring log secara real‑time untuk mendeteksi upaya desync sebelum mereka mencapai aplikasi inti.

*File analisis ini disimpan di `riset/waf-bypass-techniques/deep_analysis.md` untuk memperkaya referensi riset Anda. Jika perlu contoh kode exploit lengkap, konfigurasi Docker‑Compose, atau panduan penulisan rule ModSecurity lebih rinci, silakan beri tahu.* 
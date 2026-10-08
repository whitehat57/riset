# Pemetaan Teknik Manipulasi HTTP Header untuk Bypass WAF & Perlindungan DDoS

*Tujuan*: memberikan ringkasan 5 teknik manipulasi header modern yang sering digunakan untuk menyakiti parsing proxy depan (mis. Cloudflare, AWS WAF, Nginx, HAProxy, dll) sehingga payload dapat melintang tanpa terdeteksi oleh sistem mitigasi DDoS atau WAF.

---

## 1. CL.TE (Content-Length vs Transfer‑Encoding)

### Cara kerja teknis
- **Frontend** (mis. Cloudflare) membaca header `Content‑Length` dan menganggap panjang body sesuai nilai tersebut, lalu meneruskan data hingga byte yang ditentukan ke backend.
- **Backend** (mis. server aplikasi) mengutamakan header `Transfer‑Encoding: chunked` dan membaca body sebagai rangkaian chunk hingga menemukan chunk ukuran nol.
- Jika attacker menyisipkan kedua header dengan nilai yang bertentangan, frontend akan berhenti membaca body lebih awal, sementara backend akan terus membaca data yang seharusnya termasuk dalam chunk berikutnya sebagai permintaan HTTP baru (request smuggling).

### Mengapa mitigasi DDoS gagal
- Sistem mitigasi DDoS (rate‑limiting, challenge‑JS, bot‑score) biasanya bekerja pada tingkat **frontend** setelah header di‑parse dan sebelum mensirkulasi request ke origin. Karena frontend mengira request selesai pada `Content‑Length`, ia tidak melihat data “extra” yang akan diinterpretasikan backend sebagai request kedua.hasilnya, traffic yang sebenarnya berisi dua request terlihat sebagai satu request biasa, sehingga tidak memicu ambang batas rate‑limit atau perilaku anomali yang Dideteksi oleh sistem DDoS.

### Lab lokal (Burp Suite / curl)

**Setup**: jalankan dua proxy sederhana yang menyimulasikan perbedaan parsing:
- **Frontend proxy** (mis. `nghttpd` atau `nginx` yang hanya menggunakan `Content‑Length`).
- **Backend server** (mis. Python `http.server` yang mengikuti `Transfer‑Encoding: chunked`).

**Contoh curl**:
```bash
# Frontend mendengarkan di localhost:8080, backend di localhost:8081
curl -v http://localhost:8080/ \
  -H "Content-Length: 13" \
  -H "Transfer-Encoding: chunked" \
  -d $'0\r\n\r\nGET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n'
```
Penjelasan:
- `Content-Length: 13` menyebabkan frontend membaca 13 byte body (yaitu `0\r\n\r\nGET /a` ...).  
- Backend melihat `Transfer‑Encoding: chunked`, menginterpretasikan chunk ukuran nol (`0\r\n\r\n`) sebagai akhir body, lalu membaca sisa data sebagai permintaan baru (`GET /admin ...`).

**Burp Suite**:
1. Aktifkan *Intercept* dan tulis request manual seperti di atas.
2. Kirim ke *Repeater* dan ubah header sesuai kebutuhan.
3. Observasi respons: Anda akan melihat respons dari `/admin` meskipun path awalnya `/`.

---

## 2. TE.CL (Transfer‑Encoding vs Content‑Length)

### Cara kerja teknis
- **Frontend** mengutamakan `Transfer‑Encoding: chunked` dan membaca body sebagai chunk.
- **Backend** hanya mempercayai `Content‑Length` dan menganggap body selesai setelah byte yang ditentukan.
- Penyisipan `Transfer‑Encoding` yang mengandung chunk berukuran tidak nol diikuti oleh data tambahan membuat frontend terus membaca chunk, sementara backend berhenti lebih awal, sehingga sisa chunk dianggap sebagai request berikutnya.

### Mengapa mitigasi DDoS gagal
Sama seperti CL.TE, pengecekan anisotropi dilakukan hanya pada satu sisi (frontend atau backend). Sistem DDoS yang hanya memeriksa jumlah koneksi atau volume traffic dari sisi frontend tidak akan melihat request kedua yang diciptakan oleh backend karena ia menganggap traffic tersebut masih dalam rangkaian chunk pertama.

### Lab lokal
```bash
curl -v http://localhost:8080/ \
  -H "Transfer-Encoding: chunked" \
  -H "Content-Length: 0" \
  -d $'5\r\nhello\r\n0\r\n\r\nGET /debug HTTP/1.1\r\nHost: localhost\r\n\r\n'
```
Frontend membaca chunk `"hello"` (5 byte) lalu chunk nol (akhir), sementara backend melihat `Content-Length: 0` dan tidak membaca body sama sekali, sehingga data setelah chunk nol dianggap sebagai request baru.

---

## 3. TE.TE (Double Transfer‑Encoding)

### Cara kerja teknis
Beberapa middleware men‑normalize header dengan menggabungkan nilai `Transfer‑Encoding` (mis. menambahkan `chunked` bila belum ada). Jika attacker mengirim dua header `Transfer‑Encoding` dengan nilai yang berbeda (mis. `Transfer‑Encoding: chunked, compress` dan `Transfer‑Encoding: chunked`), maka:
- **Frontend** mungkin hanya melihat nilai pertama atau menggabungkan mereka secara salah.
- **Backend** mungkin men‑parse nilai kedua sehinggainterpretasi chunk berbeda.
Ketika parsing tidak konsisten, bisa terjadi **desync** di mana bagian body yang dianggap sebagai chunk oleh satu pihak dianggap sebagai data mentah oleh pihak lain, memberi peluang untuk menyiapkan request kedua.

### Mengapa mitigasi DDoS gagal
Sistem anti‑bot biasanya inspeksi header untuk menandai permintaan yang mencurigakan (mis. header duplicate). Namun, banyak WAF mengabaikan duplikasi header jika nilai sama atau jika mereka men‑normalize dengan menggabungkan nilai yang sama. Teknik TE.TE memanfaatkan hal itu dengan memberikan nilai yang *tidak sama* sehingga normalisasi gagal dan satu sisi melihat satu set chunk sementara sisi lain melihat yang lain, membuat traffic terlihat seperti satu request biasa bagi sistem rate‑limit.

### Lab lokal
```bash
curl -v http://localhost:8080/ \
  -H "Transfer-Encoding: chunked" \
  -H "Transfer-Encoding: identity" \
  -d $'4\r\nwiki\r\n0\r\n\r\nGET /internal HTTP/1.1\r\nHost: localhost\r\n\r\n'
```
Frontend (menggunakan `chunked`) membaca chunk `"wiki"` lalu chunk nol; backend (menggunakan `identity`) menganggap seluruh body sebagai data mentah hingga `Content‑Length` (jika ada) atau koneksi ditutup, sehingga data setelah chunk nol dianggap sebagai permintaan baru.

---

## 4. Manipulasi Hop‑by‑ Hop Header (mis. `Connection: keep-alive, X‑Forwarded‑For` + `Proxy‑Authorization`)

### Cara kerja teknis
Beberapa proxy memperlakukan header yang terdaftar dalam daftar **hop‑by‑ hop** (seperti `Connection`, `Keep‑Alive`, `Transfer‑Encoding`, `Upgrade`, `Proxy‑Authorization`) sebagai hanya relevan untuk koneksi saat ini dan tidak harus diteruskan ke backend. Namun, bila header tersebut diset dengan nilai yang **mengubah perilaku parsing** (mis. `Connection: close` menyebabkan frontend menutup koneksi prematurely, atau `Proxy‑Authorization: Basic ...` yang menyebabkan frontend men‑autentikasi dan meng‑strip header sebelum meneruskan), maka:
- Frontend mungkin menganggap request selesai dan menutup koneksi atau mengubahnya.
- Backend tetap menerima data yang belum sepenuhnya terbaca, membaca sisa sebagai request baru.

### Mengapa mitigasi DDoS gagal
Sistem DDoS sering kali fokus pada volume dan pola header umum (mis. `User‑Agent`, `Accept`). Mereka tidak secara luas men‑inspeksi apakah header hop‑by‑ hop yang dapat mengubah alur koneksi sedang dimanipulasi, sehingga request yang berhasil “desync” tidak memicu tanda tangan yang diketahui.

### Lab lokal
```bash
curl -v http://localhost:8080/ \
  -H "Connection: keep-alive" \
  -H "Proxy-Authorization: Basic dXNlcjpwYXNz" \
  -d $'GET /path HTTP/1.1\r\nHost: localhost\r\n\r\n'
```
Pada frontend yang mem‑process `Proxy‑Authorization`, header itu di‑strip dan koneksi dianggap masih aktif, sementara backend yang tidak mengenal header proxy akan membaca data setelah CRLF sebagai request baru.

---

## 5. Custom Header Injection yang Memicu Kekacauan Parsian (mis. `X‑Original‑URL`, `X‑Rewrite‑URL`, `X‑Forwarded‑Host`)

### Cara kerja teknis
Beberapa WAF atau reverse proxy menggunakan header custom untuk **overriding** target URI (mis. `X‑Original‑URL: /admin`). Frontend mungkin menggunakan header ini untuk menormalisasi atau membuat keputusan regulasi, sementara backend mengabaikannya dan menggunakan path dari request line asli. Jika attacker menyetel header ini ke nilai yang **berbeda** dari path sebenarnya, maka:
- Frontend melihat request sebagai benign (mis. `/index`) dan tidak men-trigger rule WAF.
- Backend melihat request yang sebenarnya (mis. `/admin`) dan melaksanakannya.

Sama halnya dapat terjadi dengan header yang memengaruhi parsing panjang body (mis. `X‑Content‑Length‑Override`) jika middleware mempercayainya.

### Mengapa mitigasi DDoS gagal
Karena mitigasi DDoS terutama berbasis pada **metadata koneksi** (jumlah request per IP, distribusi geolokasi, perilaku TLS), perubahan URI via header custom tidak memengaruhi metrik tersebut; traffic masih terlihat sebagai request biasa dariIP yang sama, sehingga tidak melebihi ambang batas atau memicu challenge.

### Lab lokal
```bash
curl -v http://localhost:8080/index.php \
  -H "X-Original-URL: /admin/dashboard" \
  -H "Host: vulnerable.app"
```
Frontend (mis. Cloudflare rule) mungkin hanya melihat path `/index.php` dan tidak men‑trigger rule pembatasan akses `/admin`. Backend (aplikasi) melihat header `X-Original-URL` dan meng‑override target ke `/admin/dashboard`, sehingga mengakses halaman terlindungi tanpa terdeteksi.

---

## Ringkasan Teknik & Rekomendasi Deteksi

| Teknik | Prinsip Desync | Mengapa WAF/DDoS Sisip | Cara Deteksi (pada sisi frontend) |
|--------|----------------|------------------------|-----------------------------------|
| CL.TE  | Content‑Length vs Transfer‑Encoding | Frontend hanya melihat satu panjang body | Normalisasi paksa: jika kedua header ada, tolak atau lakukan re‑parse dengan kedua standar dan bandingkan hasil |
| TE.CL  | Transfer‑Encoding vs Content‑Length | Sama dengan CL.TE tapi balik | Sama – paksa satu standar (baik TE maupun CL) dan validasi panjang body |
| TE.TE  | Ganda Transfer‑Encoding dengan nilai berbeda | Normalisasi header mungkin gagal | Tolak header Transfer‑Encoding duplikasi atau paksa nilai kanonikal (hanya `chunked`) |
| Hop‑by‑ Hop | Manipulasi Connection, Proxy‑Authorization, dll | Header ini biasanya di‑strip/diabaikan, tidak diperiksa untuk efek samping | Memeriksa nilai header hop‑by‑ hop untuk anomali (mis. `Connection: close` dengan body non‑zero) |
| Custom Override | Header override URI atau panjang body | DIDS tidak meng‑inspeksi semantic override | Mencegah penggunaan header override yang tidak dokumentasi; enforce strict allow‑list header yang diperoleh dari backend |

Dengan memahami mekanisme di atas, tim red‑team dapat merancang uji penetrasi yang lebih realistis, sementara tim blue‑team dapat menambahkan aturan normalisasi dan validasi ketat pada lapisan proxy/WAF agar tidak lagi rentan terhadap desync HTTP header.

---
*File ini disimpan di `riset/waf-bypass-techniques/technique_map.md` untuk referensi riset selanjutnya.* 
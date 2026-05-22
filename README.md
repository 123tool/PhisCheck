## 🛰️ PhisCheck - Phising Monitor Console

---

**PhisCheck** adalah sebuah platform simulasi dasbor pemantauan intelijen ancaman (*Threat Intelligence Monitor*) yang dikemas dalam antarmuka konsol peretas (*Hacker Console*) berbasis web.

Alat ini dirancang khusus untuk mensimulasikan bagaimana seorang analis keamanan siber (*Cyber Security Analyst*) atau tim OSINT melacak, menyaring, dan memitigasi ancaman digital secara realtime.

Fokus utama dari PhisCheck adalah memantau pergerakan pendaftaran domain mencurigakan di internet yang berpotensi digunakan untuk aksi **Phishing**, **Typosquatting** (pelesetan nama domain), maupun penipuan online yang menargetkan *brand* atau institusi besar.


---

## 🛠️ Bagaimana Cara Kerjanya?
Sistem pada PhisCheck bekerja melalui 3 komponen utama yang berjalan secara asinkron di latar belakang:
1. **Ingestor Aliran Data (Live Feed Ingestion):** Sistem mensimulasikan penyerapan data sertifikat SSL baru yang terbit di seluruh dunia secara konstan.
2. **Mesin Heuristik & Deteksi Kamus (Heuristic Engine):** Setiap domain yang lewat akan diperiksa menggunakan algoritma pencocokan string. Jika domain tersebut mengandung kata kunci sensitif (seperti nama bank, e-commerce, atau media sosial) namun menggunakan struktur yang tidak sah, sistem otomatis menaikkan status bahaya (*ALERT*).
3. **Analisis Manual via Konsol (Interactive CLI):** Pengguna dapat bertindak sebagai operator penegak keamanan dengan mengetikkan perintah langsung ke dalam terminal untuk menginvestigasi domain tertentu secara mandiri.

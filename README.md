# Cryptograph Encrypt Decrypt

## Deskripsi
Cryptograph Encrypt Decrypt adalah aplikasi web yang memungkinkan pengguna untuk mengenkripsi dan mendekripsi pesan menggunakan berbagai algoritma kriptografi. Aplikasi ini dibangun menggunakan Streamlit dan mendukung beberapa metode enkripsi seperti RSA, Triple DES, Blowfish, dan Caesar Cipher.

## Fitur
- **Enkripsi dan Dekripsi**: Mendukung berbagai algoritma kriptografi.
- **Antarmuka Pengguna yang Ramah**: Menggunakan Streamlit untuk pengalaman pengguna yang interaktif.
- **Informasi tentang Algoritma**: Menyediakan penjelasan tentang setiap algoritma yang digunakan.

## Algoritma yang Didukung
1. **RSA**: Algoritma kriptografi asimetris yang digunakan untuk enkripsi dan tanda tangan digital.
2. **Triple DES**: Peningkatan dari DES yang menggunakan tiga blok kunci untuk meningkatkan keamanan.
3. **Blowfish**: Cipher blok kunci simetris yang cepat dan aman.
4. **Caesar Cipher**: Cipher substitusi sederhana yang menggeser huruf dalam pesan.

## Instalasi
Untuk menjalankan aplikasi ini, Anda perlu menginstal beberapa dependensi. Anda dapat menggunakan pip untuk menginstalnya:


```pip install streamlit pycryptodome rsa```


## Cara Menjalankan
Setelah semua dependensi terinstal, Anda dapat menjalankan aplikasi dengan perintah berikut:


```streamlit run encryptdecrypt.py```

Kemudian, buka browser Anda dan akses `http://localhost:8501` untuk melihat aplikasi.

## Kontribusi
Jika Anda ingin berkontribusi pada proyek ini, silakan buat fork dari repositori ini dan kirim pull request dengan perubahan Anda.

## Lisensi
Proyek ini dilisensikan di bawah MIT License. Lihat file LICENSE untuk detail lebih lanjut.

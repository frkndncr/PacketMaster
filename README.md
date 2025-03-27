# PacketMaster 🛡️

![GitHub stars](https://img.shields.io/github/stars/frkndncr/packetmaster.svg?style=social&label=Star&maxAge=2592000)
![License](https://img.shields.io/badge/License-MIT-blue.svg)
![Python Version](https://img.shields.io/badge/python-3.7%2B-blue)

**Güçlü ve Kullanıcı Dostu Ağ Paket Yakalama ve Analiz Aracı**

PacketMaster, ağ trafiğinizi kolayca yakalamanıza, filtrelemenize ve analiz etmenize olanak tanıyan açık kaynaklı bir araçtır. Güvenlik uzmanları, ağ yöneticileri veya ağ trafiğini anlamak isteyen herkes için uygundur.

![PacketMaster Demo](screenshots/demo.gif)

## 🌟 Özellikler

- 🔍 **Gelişmiş Filtreleme**: IP, port, protokol ve içerik tabanlı filtreler
- 🔐 **Güvenlik Analizi**: Kimlik bilgisi sızıntısı ve anahtar kelime tespiti
- 📊 **Gerçek Zamanlı İstatistikler**: Ağ trafiğiniz hakkında anında bilgi
- 📝 **HTTP/HTTPS İnceleme**: Web trafiği detaylı analizi
- 🧩 **Esnek Çıktı**: JSON veya düz metin formatında çıktı seçenekleri
- 🎨 **Renkli Konsol**: Kolay okunabilir renkli terminal çıktısı
- 🌐 **Tüm Platformlar**: Linux, macOS ve Windows desteği

## 📋 Gereksinimler

- Python 3.7+
- Scapy
- Root/Administrator yetkileri (paket yakalama işlemi için)

## 🚀 Kurulum

```bash
# Gerekli paketi yükle
pip install scapy

# GitHub'dan indir
git clone https://github.com/frkndncr/PacketMaster
cd packetmaster

# Komut dosyasını çalıştırılabilir yap
chmod +x packetmaster.py
```

## 🎮 Kullanım

### Temel Kullanım

```bash
# Tüm paketleri yakala
sudo python packetmaster.py

# Belirli bir arayüzü kullan
sudo python packetmaster.py -i eth0

# Belirli portları izle
sudo python packetmaster.py -p 80 443 8080
```

### Gelişmiş Kullanım

```bash
# Anahtar kelime arama
sudo python packetmaster.py -k password credentials login

# Belirli IP adresleri veya ağları izleme
sudo python packetmaster.py -ip 192.168.1.1 -n 10.0.0.0/24

# Özel filtre ile kullanım ve dosyaya kaydetme
sudo python packetmaster.py -f "tcp port 80 or port 443" -o capture.json

# Düzenli istatistik gösterimi
sudo python packetmaster.py -s
```

### Tüm Komut Seçenekleri

```
-i, --interface    Ağ arayüzü (örn. eth0, wlan0)
-f, --filter       BPF filtresi (örn. "tcp port 80")
-p, --port         Port numaraları (örn. 80 443 8080)
-ip, --ip          IP adresleri (örn. 192.168.1.1)
-n, --net          Ağ adresleri (örn. 192.168.1.0/24)
-pr, --protocol    Protokoller (tcp, udp, icmp)
-c, --count        Yakalanacak paket sayısı (0=sınırsız)
-k, --keyword      Aranacak anahtar kelimeler (örn. "login password")
-o, --output       Çıktı dosyası (örn. capture.txt veya capture.json)
-s, --stats        Her 10 saniyede bir istatistik göster
-q, --quiet        Sessiz mod, sadece önemli paketleri göster
```

## 🛠️ Katkıda Bulunma

Katkıda bulunmak istiyorsanız:

1. Bu repo'yu forklayın
2. Özellik dalı oluşturun (`git checkout -b yeni-ozellik`)
3. Değişikliklerinizi commit edin (`git commit -m 'Yeni özellik: XYZ eklendi'`)
4. Dalınıza push yapın (`git push origin yeni-ozellik`)
5. Bir Pull Request açın

## 📝 Yapılacaklar Listesi

- [ ] GUI arayüzü ekleme
- [ ] Paket içeriklerinde gelişmiş arama
- [ ] Daha fazla protokol analizi ekleme
- [ ] Otomatik uyarı sistemi
- [ ] Paket yakalama ve analiz sonuçlarını kaydetme/yükleme
- [ ] Daha fazla dil desteği

## 📜 Lisans

Bu proje MIT lisansı altında lisanslanmıştır - detaylar için [LICENSE](LICENSE) dosyasına bakınız.

## 🙏 Teşekkürler

- [Scapy](https://scapy.net/) - Muhteşem paket manipülasyon kütüphanesi

---

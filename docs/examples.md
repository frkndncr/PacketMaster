# PacketMaster Kullanım Örnekleri

Bu belge, PacketMaster'ın yaygın kullanım senaryolarını ve örnek komutları gösterir.

## Temel Kullanım

### Tüm Paketleri Yakalama

En basit kullanımda, varsayılan ağ arayüzündeki tüm paketleri yakalayabilirsiniz:

```bash
sudo python packetmaster.py
```

### Belirli Ağ Arayüzünü Kullanma

```bash
# Ethernet arayüzünden paketleri yakala
sudo python packetmaster.py -i eth0

# Kablosuz arayüzden paketleri yakala
sudo python packetmaster.py -i wlan0
```

### Sınırlı Sayıda Paket Yakalama

```bash
# 100 paket yakala ve dur
sudo python packetmaster.py -c 100
```

## Filtreler

### Port Tabanlı Filtreleme

```bash
# Sadece HTTP (80) ve HTTPS (443) trafiğini yakala
sudo python packetmaster.py -p 80 443

# Birden çok port monitörleme
sudo python packetmaster.py -p 80 443 8080 22
```

### IP Tabanlı Filtreleme

```bash
# Belirli bir IP adresine giden/gelen trafiği izle
sudo python packetmaster.py -ip 192.168.1.1

# Birden çok IP adresi izleme
sudo python packetmaster.py -ip 192.168.1.1 10.0.0.1 8.8.8.8
```

### Ağ (Subnet) Tabanlı Filtreleme

```bash
# Belirli bir ağdaki tüm trafiği izle
sudo python packetmaster.py -n 192.168.1.0/24

# Birden çok ağ izleme
sudo python packetmaster.py -n 192.168.1.0/24 10.0.0.0/16
```

### Protokol Tabanlı Filtreleme

```bash
# Sadece TCP trafiğini izle
sudo python packetmaster.py -pr tcp

# TCP ve UDP trafiğini izle
sudo python packetmaster.py -pr tcp udp

# Sadece ICMP (ping) trafiğini izle
sudo python packetmaster.py -pr icmp
```

### BPF Formatı ile Özel Filtreler

[Berkeley Packet Filter (BPF)](https://biot.com/capstats/bpf.html) formatında gelişmiş filtreler kullanabilirsiniz:

```bash
# DNS trafiğini yakala
sudo python packetmaster.py -f "udp port 53"

# HTTP trafiğinin içeriğini filtrele
sudo python packetmaster.py -f "tcp port 80 and (tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420)"

# Sadece SSH hariç tüm trafiği izle
sudo python packetmaster.py -f "not port 22"
```

## İçerik Analizi

### Anahtar Kelime Arama

```bash
# Hassas bilgileri ara
sudo python packetmaster.py -k password username login

# Birden çok anahtar kelimenin geçtiği paketleri filtrele
sudo python packetmaster.py -k password sifre admin root
```

## Çıktı Seçenekleri

### Sessiz Mod

```bash
# Sadece önemli paketleri göster (anahtar kelime eşleşmeleri ve kimlik bilgileri)
sudo python packetmaster.py -q
```

### Düzenli İstatistikler

```bash
# Her 10 saniyede bir istatistik göster
sudo python packetmaster.py -s
```

### Dosyaya Kaydetme

```bash
# Yakalanan paketleri metin dosyasına kaydet
sudo python packetmaster.py -o capture.txt

# JSON formatında kaydet (daha sonra işlemek için)
sudo python packetmaster.py -o capture.json
```

## Kombine Kullanım Örnekleri

### Güvenlik İzleme Senaryosu

Ağınızdaki potansiyel güvenlik sorunlarını izlemek için:

```bash
sudo python packetmaster.py -i eth0 -p 80 443 8080 22 21 -k password username login admin root private -s -o security_audit.json
```

Bu komut:
- HTTP, HTTPS, alternatif HTTP, SSH ve FTP trafiğini izler
- Hassas anahtar kelimeleri arar
- 10 saniyede bir istatistik gösterir
- Sonuçları JSON dosyasına kaydeder

### HTTP/HTTPS Trafik Analizi

Web trafiğini izlemek için:

```bash
sudo python packetmaster.py -pr tcp -p 80 443 8080 -f "tcp port 80 or tcp port 443 or tcp port 8080" -o web_traffic.txt
```

Bu komut:
- Sadece web trafiğini izler (HTTP ve HTTPS)
- BPF filtresi ile daha kesin seçim yapar
- Sonuçları düz metin dosyasına kaydeder

### Ağ Keşfi

Ağınızdaki cihazları ve iletişim modellerini anlamak için:

```bash
sudo python packetmaster.py -n 192.168.1.0/24 -c 1000 -s -o network_discovery.json
```

Bu komut:
- Yerel ağınızdaki tüm trafiği izler
- 1000 paket yakalar
- Düzenli istatistikler gösterir
- Sonuçları JSON dosyasına kaydeder

## Özelleştirilmiş Senaryolar

### DNS Trafiği İzleme

```bash
sudo python packetmaster.py -f "udp port 53" -o dns_queries.txt
```

### SSH Bağlantı Girişimleri İzleme

```bash
sudo python packetmaster.py -p 22 -k password -s
```

### Sadece Şüpheli Trafiği Kaydetme

```bash
sudo python packetmaster.py -q -k hack attack admin root password -o suspicious.json
```

## İpuçları ve Püf Noktaları

1. **Performans**: Büyük ağlarda, belirli filtreleri kullanarak yakalanan paket sayısını sınırlandırın
2. **Hassas Bilgiler**: Yakalanan paketler şifreler ve özel bilgiler içerebilir, dikkatli olun
3. **Hata Ayıklama**: Bir sorunla karşılaşırsanız, sessiz modu kapatın ve tüm çıktıyı görüntüleyin
4. **Hız vs. Derinlik**: Daha fazla analiz daha fazla CPU kaynağı gerektirir, gerektiğinde anahtar kelime aramasını kapatın
5. **Görselleştirme**: Çıktınızı JSON olarak kaydedip daha sonra görselleştirme araçlarıyla analiz edebilirsiniz
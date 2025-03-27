# PacketMaster Kurulum Rehberi

Bu belge, PacketMaster'ı farklı işletim sistemlerine kurma adımlarını içerir.

## Gereksinimler

- Python 3.7 veya üstü
- pip (Python paket yöneticisi)
- Yönetici/Root yetkileri (paket yakalama için)
- Internet bağlantısı (bağımlılıkları indirmek için)

## Hızlı Kurulum

### 1. Python Kurulumu

PacketMaster Python 3.7 veya üstü gerektirir. İşletim sisteminize göre Python'u yükleyin:

- **Windows**: [Python.org](https://www.python.org/downloads/windows/) adresinden indirin ve kurun
- **Linux**: `sudo apt install python3 python3-pip` (Debian/Ubuntu) veya `sudo dnf install python3 python3-pip` (Fedora)
- **macOS**: `brew install python` (Homebrew ile) veya [Python.org](https://www.python.org/downloads/mac-osx/) adresinden indirin

Python sürümünüzü kontrol edin:
```bash
python --version
# veya
python3 --version
```

### 2. Libpcap/Npcap Kurulumu

Scapy kütüphanesi paket yakalama için düşük seviyeli bir paket yakalama kütüphanesine ihtiyaç duyar:

- **Windows**: [Npcap](https://nmap.org/npcap/) indirin ve kurun
- **Linux**: `sudo apt install libpcap-dev` (Debian/Ubuntu) veya `sudo dnf install libpcap-devel` (Fedora)
- **macOS**: `brew install libpcap` (genellikle yüklü gelir)

### 3. PacketMaster'ı İndirme

```bash
# GitHub'dan klonlama
git clone https://github.com/yourusername/packetmaster.git
cd packetmaster

# Veya ZIP olarak indirme seçeneği mevcuttur
# https://github.com/yourusername/packetmaster/archive/main.zip
```

### 4. Bağımlılıkları Yükleme

```bash
pip install -r requirements.txt
# veya
pip3 install -r requirements.txt
```

## İşletim Sistemine Özel Kurulum Talimatları

### Linux

Linux'ta paket yakalama için root yetkileri gerekir:

```bash
# Bağımlılıkları yükle
sudo apt update
sudo apt install python3-dev python3-pip libpcap-dev

# Scapy yükle
pip3 install scapy

# İzinleri ayarla
chmod +x packetmaster.py

# Çalıştır
sudo ./packetmaster.py
```

#### Pip olmadan doğrudan çalıştırma
```bash
# Scapy'yi doğrudan pip ile yüklemek yerine sistem paketini kullanma seçeneği
sudo apt install python3-scapy
sudo ./packetmaster.py
```

### Windows

Windows'ta Npcap yüklemeniz gerekir:

1. [Npcap](https://nmap.org/npcap/) indirin ve kurun
2. Python ve pip'in PATH'e eklendiğinden emin olun
3. Komut istemini yönetici olarak açın

```bash
# Scapy yükle
pip install scapy

# Çalıştır (yönetici olarak)
python packetmaster.py
```

### macOS

macOS'ta paket yakalama için root yetkileri gerekir:

```bash
# Homebrew ile libpcap yükle
brew install libpcap

# Scapy yükle
pip3 install scapy

# İzinleri ayarla
chmod +x packetmaster.py

# Çalıştır
sudo ./packetmaster.py
```

## Doğrulama

Kurulumun başarılı olup olmadığını kontrol etmek için:

```bash
# Root/Yönetici olarak
sudo ./packetmaster.py -i lo -c 10

# Veya
sudo python3 packetmaster.py -i lo -c 10
```

Bu komut, yerel ağ arayüzünden 10 paket yakalamalı ve görüntülemelidir.

## Sorun Giderme

### Sık Karşılaşılan Sorunlar

#### "Permission Denied" Hatası
```
Permission denied while opening eth0
```
**Çözüm**: Paket yakalama için yönetici/root yetkileri gereklidir. Komutu `sudo` ile çalıştırın.

#### "Libpcap Not Found" Hatası
```
ImportError: libpcap tidak ditemukan, Scapy tidak berfungsi tanpa itu
```
**Çözüm**: Libpcap'i yükleyin: `sudo apt install libpcap-dev` (Linux) veya Npcap'i yükleyin (Windows).

#### "No Module Named Scapy" Hatası
```
ModuleNotFoundError: No module named 'scapy'
```
**Çözüm**: Scapy'yi yükleyin: `pip install scapy` veya `pip3 install scapy`.

### Yardım ve Destek

Kurulumla ilgili sorularınız veya sorunlarınız varsa:

1. GitHub Issues üzerinden bir sorun açın
2. Hatayı ayrıntılarıyla açıklayın
3. İşletim sisteminizi, Python sürümünüzü ve hata mesajını belirtin

GitHub Sorun Bildirimi: [https://github.com/yourusername/packetmaster/issues](https://github.com/yourusername/packetmaster/issues)
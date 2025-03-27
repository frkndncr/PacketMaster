# Katkıda Bulunma Rehberi

PacketMaster'a katkıda bulunmak istediğiniz için teşekkür ederiz! Bu belge, projeye katkıda bulunmak isteyenler için rehber niteliğindedir.

## Nasıl Başlamalı?

1. Repo'yu forklayın
2. Yerel makinenize klonlayın: `git clone https://github.com/YOUR-USERNAME/packetmaster.git`
3. Bağımlılıkları yükleyin: `pip install -r requirements.txt`
4. Yeni bir dal oluşturun: `git checkout -b yeni-ozellik`
5. Değişikliklerinizi yapın ve commit'leyin: `git commit -m 'Yeni özellik eklendi: XYZ'`
6. Dalınıza push yapın: `git push origin yeni-ozellik`
7. Pull Request açın!

## Geliştirme Rehberi

### Kod Stili

- PEP 8 standartlarını takip edin
- Anlamlı değişken ve fonksiyon isimleri kullanın
- Her fonksiyon ve sınıf için docstring ekleyin
- Karmaşık kod bloklarını açıklayan yorumlar ekleyin

### Testler

Yeni bir özellik eklerken veya bir hata düzeltirken, ilgili test ekleyin:

```python
# tests/test_packetmaster.py içinde
def test_new_feature():
    # Test kodu
    assert result == expected
```

### Pull Request Süreci

1. PR açmadan önce tüm testlerin geçtiğinden emin olun
2. PR açarken değişikliklerinizi detaylı açıklayın
3. Mümkünse ekran görüntüleri veya örnekler ekleyin
4. Bir yönetici PR'nizi inceleyecek ve geri bildirimde bulunacaktır

## Özellik Talepleri ve Hata Bildirimleri

- Yeni bir özellik talep etmek için GitHub Issues üzerinden "enhancement" etiketi ile bir issue açın
- Bir hata bildirmek için aşağıdaki bilgileri içeren bir issue açın:
  - Hatanın detaylı açıklaması
  - Hatayı yeniden oluşturmak için adımlar
  - Beklenen davranış vs. gerçekleşen davranış
  - İşletim sistemi, Python sürümü, vs.

## Proje Vizyonu

PacketMaster, kullanım kolaylığı ve fonksiyonelliği dengeleyerek, ağ trafiğini anlamak ve analiz etmek isteyen herkes için güçlü bir araç olmayı hedefliyor. Katkılarınızı bu vizyona uygun şekilde yapmanızı rica ederiz.

### Öncelikli Alanlar

Aşağıdaki alanlarda katkılar özellikle değerlidir:

1. Performans iyileştirmeleri
2. Yeni protokol analizleri
3. İçerik arama ve analiz yeteneklerinin geliştirilmesi
4. Belgelendirmenin iyileştirilmesi
5. Kullanım kolaylığını artıracak iyileştirmeler

## Lisans

Katkıda bulunarak, katkılarınızın projenin [MIT Lisansı](LICENSE) altında yayınlanacağını kabul etmiş olursunuz.
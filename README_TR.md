# Ağ Trafiği İzleme ve Anomali Tespiti

Bu proje, One-Class SVM ile normal ağ trafiğinden farklı davranan zaman pencerelerini işaretler. Windows için hazırlanmış araştırma ve portföy prototipidir. Algoritmanın verdiği `ANOMALI` uyarısı bir saldırı tanısı değildir: büyük bir indirme, yeni bir uygulama veya farklı günlük kullanım da uyarı üretebilir.

İlk çalıştırma için `BASLA_BURADAN.txt` dosyasını kullan. Önce çevrimdışı smoke test, ardından canlı yakalama yapılır. Yapay verilerin testinden başarı yüzdesi çıkarılmaz.

## Dosyalar

- `network_monitor/features.py`: paket başlıklarından zaman penceresi özellikleri.
- `network_monitor/capture.py`: TShark ile canlı ve PCAP okuma.
- `network_monitor/model.py`: normal referans verisinden One-Class SVM eğitimi.
- `network_monitor/cli.py`: toplama, eğitim, canlı izleme ve kayıt tekrarı komutları.
- `smoke_test.py`: Wireshark kurmadan bütün çevrimdışı akışı sınar.
- `tests/test_pipeline.py`: özellikler, veri sınırları, model kayıtları ve yakalama sürecinin kontrolleri.
- `backup.py`: kodu ve isteğe bağlı sonuçları ZIP olarak yedekler.
- `VALIDATION.md`: hangi kontrollerin yapıldığını açıklar.

## 1 Projeyi kur

ZIP dosyasını aç ve `network_anomaly_detection` klasörünü örneğin `Desktop\projects` içine yerleştir. Bu klasörde `smoke_test.py`, `requirements.txt` ve `network_monitor` birlikte görünmelidir. PowerShell'i klasörde aç.

```powershell
py -3 --version
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe smoke_test.py
```

Python 3.11 veya daha yeni bir sürüm kullan. `py` bulunamazsa bilgisayarındaki Python ile `python -m venv .venv` kullanabilirsin. Sanal ortamı etkinleştirmek şart değildir; komutlar doğrudan bu ortamın Python'unu çalıştırır. `.env` dosyası veya API anahtarı gerekmiyor.

Beklenen son satır: `SMOKE TEST PASSED`. Veri dosyaları geçici klasörde oluşturulur ve test sonunda temizlenir. Wireshark bu aşamada gerekli değildir.

## 2 Wireshark ve TShark kurulumu

Wireshark'ı resmi indirme sayfasından al: https://www.wireshark.org/download.html

Windows kurulumunda **TShark** bileşenini ve canlı yakalama için **Npcap** kurulumunu seç. Kurulum ayrıntıları: https://www.wireshark.org/docs/wsug_html_chunked/ChBuildInstallWinInstall.html

Ardından:

```powershell
.\.venv\Scripts\python.exe -m network_monitor.cli interfaces
```

Liste içinden kullandığın Wi-Fi veya Ethernet bağlantısının numarasını bul. Aşağıdaki örneklerde `3` kullanılmıştır; bunu kendi listendeki numarayla değiştir. VPN, loopback ve sanal adaptörler farklı bir trafik görünümü verir. Adaptör numarası değişebileceği için yeniden başlatma veya yeni bağlantı sonrasında listeyi tekrar kontrol et.

TShark standart Windows yolunda otomatik bulunur. Farklı klasöre kurulduysa:

```powershell
.\.venv\Scripts\python.exe -m network_monitor.cli interfaces --tshark "D:\Wireshark\tshark.exe"
```

Bu seçenek collect, monitor ve export-pcap komutlarında da kullanılabilir. Yakalama izni hatası varsa Npcap ayarlarını kontrol et. Npcap yalnızca yöneticilere izin verecek şekilde kurulmuşsa PowerShell'i yönetici olarak açman gerekebilir. Kod bu yetkiyi kendisi yükseltmez.

## 3 Normal kullanım kaydı oluştur

Kendi bilgisayarında ve yakalama iznin bulunan bağlantıda çalış. Bu uygulama ağ taraması, paket üretimi veya saldırı yapmaz. Seçilen adaptörün görebildiği trafiği pasif olarak izler. Evdeki bütün cihazların trafiğini otomatik olarak göremez.

İlk prova için 15 dakika:

```powershell
.\.venv\Scripts\python.exe -m network_monitor.cli collect --interface 3 --seconds 900 --window 10 --output "data\normal_01.csv"
```

Bu sırada olağan kullanımını sürdür: internette gezinmek, mesajlaşmak ve günlük kullandığın uygulamalar. Referans veri temiz olduğu varsayılan normal kullanımı temsil etmelidir. Şüpheli bir durumu bilerek bu kayda dahil etme. Etiketlenmemiş trafiğin gerçekten normal olduğu algoritma tarafından doğrulanmaz.

10 saniyede bir kayıt mesajı görürsün. 15 dakika yaklaşık 90 pencere verir; bu başlangıç provasıdır. Daha kararlı bir eşik için temsili kullanım içeren en az bir saat önerilir:

```powershell
.\.venv\Scripts\python.exe -m network_monitor.cli collect --interface 3 --seconds 3600 --window 10 --output "data\normal_02.csv"
```

Ctrl+C ile durdurursan tamamlanan pencereler CSV'de kalır, yarım kalan pencere yazılmaz. Eğitim için en az 60 tam pencere gerekir. Dosyaların üzerine yazılmaz; yeni kayıtta yeni bir dosya adı seç. Bağlantıda hiç trafik yoksa sıfır değerli pencereler kaydedilir. Bütünüyle sabit bir kayıt model eğitimi için kabul edilmez.

## 4 Modeli eğit

Kaydın normal kullanım olduğunu gözden geçirdikten sonra:

```powershell
.\.venv\Scripts\python.exe -m network_monitor.cli train --data "data\normal_01.csv" --output "runs\ocsvm_01" --baseline-is-normal
```

Bir saatlik kaydı kullandıysan `--data` yolunu `data\normal_02.csv` yap. `--baseline-is-normal`, verinin normal olduğu varsayımını açıkça belirtir. Saldırı etiketli kayıt varsa komut eğitimi reddeder.

Normal kayıt zaman sırasıyla yaklaşık %60 eğitim, %20 eşik ayarı ve %20 normal holdout olarak ayrılır. Sınırlar arasında ikişer pencere kullanılmaz. Bu boşluk zaman bağımlılığını tamamen ortadan kaldırmaz. Rastgele satır karıştırması yapılmaz. Saldırı etiketli gerçek test seti bu pakette bulunmaz.

Çıktılar:

- `model.joblib`: ölçekleme, SVM modeli, eşik ve özellik şeması.
- `training_report.json`: ayarlar, kullanılan satır sayıları ve normal holdout uyarı oranı.
- `normal_holdout_scores.csv`: son normal bölümün skorları.
- `requirements-frozen.txt`: kullanılan Python paketlerinin sürümleri.

`normal_holdout_alert_rate` normal kabul edilen yeni pencerelerin ne kadarının işaretlendiğini anlatır; saldırı yakalama oranı veya doğruluk değildir. Kalibrasyon bölümü 100 pencereden azsa eşik tahmininin kararsız olabileceği mesajı gösterilir.

## 5 Canlı izlemeyi başlat

```powershell
.\.venv\Scripts\python.exe -m network_monitor.cli monitor --interface 3 --model "runs\ocsvm_01\model.joblib" --seconds 900 --output "runs\monitor_01.csv"
```

Modelin eğitildiği pencere uzunluğu otomatik kullanılır. Her tamamlanan pencerede `NORMAL` veya `ANOMALI`, paket ve bayt hızları, karar skoru, eşik ve model hesaplama süresi gösterilir. Küçük karar skoru daha olağandışı davranışı belirtir; eşikten küçük skor uyarı üretir. Bu skor olasılık veya saldırı yüzdesi değildir.

Olağan davranışın değişmesi yanlış alarma yol açabilir. Uyarıları uygulamalar, zaman ve Wireshark kaydıyla incele. Aynı oturum sonuçlarına bakarak sürekli eşik değiştirip bunları bağımsız nihai sonuç olarak raporlama. Model değişikliklerini yeni, zaman açısından ayrılmış oturumlarda değerlendir.

`inference_ms` yalnızca pencere özelliklerinin modele verilme süresidir. Ağ yakalama, özellik çıkarma ve 10 saniyelik pencere bekleme süresini kapsamaz. Yüksek trafik altında paket kaybı ayrıca ölçülmelidir. Model bir paketi anında sınıflandıran sistem değildir.

## 6 Kaydedilmiş veriyi tekrar oynat

Wireshark olmadan kalıcı demo oluşturmak için:

```powershell
.\.venv\Scripts\python.exe -m network_monitor.cli demo-data --output "data\demo_01"
.\.venv\Scripts\python.exe -m network_monitor.cli train --data "data\demo_01\normal.csv" --output "runs\demo_01" --baseline-is-normal
.\.venv\Scripts\python.exe -m network_monitor.cli replay --data "data\demo_01\new_session.csv" --model "runs\demo_01\model.joblib" --output "runs\demo_alerts_01.csv" --delay 0.1
```

Bu demo yalnızca matematiksel özellik vektörleri üretir. Ağ paketi göndermez. Yapay örneklerdeki uyarıları gerçek saldırı performansı olarak raporlama. Eğitimdeki CSV tekrar kullanılırsa kod bunun bağımsız değerlendirme olmadığını bildirir.

Wireshark'ta mevcut bir PCAP/PCAPNG dosyası kaydettiysen aynı özellikleri elde etmek için:

```powershell
.\.venv\Scripts\python.exe -m network_monitor.cli export-pcap --pcap "data\session.pcapng" --window 10 --output "data\session_windows_01.csv"
```

PCAP pencereleri ilk IP paketinin zamanından başlar. Son eksik pencere çıkarılır. Paket zamanları geriye gidiyorsa dosya kabul edilmez. Canlı pencereler TShark çıktısının geliş zamanını, PCAP pencereleri paket zamanını kullanır; yük veya tamponlama kaynaklı farklar değerlendirmede dikkate alınmalıdır. Başka veri setlerinden hazır CSV'ler, kolon adları aynı görünse bile aynı özellik tanımlarını kullanmayabilir.

## Algoritma ve özellikler

Her pencere için paket/saniye, bayt/saniye, ortalama ve standart sapma paket boyu, farklı IP adresi sayısı, farklı taşıma portu sayısı, TCP oranı, UDP oranı ve SYN bayrağı taşıyan paket oranı hesaplanır. IPv4 ve IPv6 desteklenir. Özellikler bütün gözlenen IP trafiğinin pencere özeti olduğu için bir hedef cihaz veya tek yönlü akış modeli değildir. Benzersiz port sayısı iki yönün portlarını birlikte içerir; geçici kaynak portları da buna dahildir.

Özelliklere `log1p`, ardından yalnızca eğitim bölümünde öğrenilen StandardScaler uygulanır. SVM ayarları RBF kernel, gamma=scale ve nu=0.05'tir. Nu, saldırı yüzdesi veya garantili yanlış alarm oranı değildir. Başlangıç eşiği normal kalibrasyon skorlarının %5 yüzdeliğiyle seçilir; yeni trafikte %5 yanlış alarm garantisi vermez. Model çevrimiçi olarak kendi kendine yeniden eğitilmez.

Özellik belleğinde IP/port kümeleri tutulur, ardından CSV'ye sadece toplulaştırılmış sayılar yazılır. Ham paket, içerik, alan adı ve IP adresleri bu proje tarafından kalıcı olarak kaydedilmez. Mevcut PCAP dosyası ise bu bilgileri içerebilir. Kaynak trafiğin davranış bilgisi modelde ve özetlerde bulunduğu için bunları paylaşmadan önce gözden geçir. Yalnızca kendin oluşturduğun veya güvendiğin `joblib` modelini yükle; bu biçim Python nesneleri içerir.

## Raspberry Pi aşaması

Kod Linux üzerinde de kullanılabilir; bu pakette Raspberry Pi üzerinde çalışma ve kaynak tüketimi henüz doğrulanmadı. Pi'nin adaptöründe görülebilen trafik ile Windows referansındaki trafik farklı olabilir; Pi için yerel bir normal referans oluşturmak gerekir. Yakalama yetkileri cihazda ayrıca ayarlanmalıdır. Python 3.11+ ortamında TShark ve scikit-learn kurulumu, gerçek yakalama ve model hızı doğrulandıktan sonra edge cihaz iddiası raporlanabilir. Büyük veride RBF One-Class SVM maliyeti artar; bu prototip en fazla 20000 pencere kabul eder.

## Yedekleme

```powershell
.\.venv\Scripts\python.exe backup.py --output "..\network_code_backup.zip"
.\.venv\Scripts\python.exe backup.py --include-runs --output "..\network_results_backup.zip"
```

Kod yedeği veri, sanal ortam ve çalıştırma sonuçlarını dışarıda tutar. İkinci komut `runs` klasörünü ekler. Gerçek normal CSV verisini ayrıca özel ve güvenilir bir konuma yedekle. Model, ayarlar ve ortam sürümlerini birlikte sakla. Yedek ZIP dosyaları mevcut dosyanın üzerine yazmaz.

## Kaynaklar

- One-Class SVM: https://scikit-learn.org/stable/modules/generated/sklearn.svm.OneClassSVM.html
- Novelty detection: https://scikit-learn.org/stable/modules/outlier_detection.html
- TShark alanları ve komutları: https://www.wireshark.org/docs/man-pages/tshark.html
- Windows kurulumu: https://www.wireshark.org/docs/wsug_html_chunked/ChBuildInstallWinInstall.html

Başarı metrikleri, canlı Windows testi ve Raspberry Pi doğrulaması gerçekleştirildikçe ayrı bir deney raporuna eklenmelidir. Kaybolan eski projenin kaynak kodu veya performansı kurtarıldığı iddia edilmez.

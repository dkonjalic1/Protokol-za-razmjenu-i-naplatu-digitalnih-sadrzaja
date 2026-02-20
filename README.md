# Protokol za razmjenu i naplatu digitalnih sadržaja

Cilj ovog projekta je dizajnirati i implementirati protokol za razmjenu i naplatu digitalnih sadržaja u okviru mreže
izdavača i pretplatnika. Protokol se sastoji iz dva dijela: server za distribuciju sadržaja i
klijentskih aplikacija korisnika. Server treba da podrži proizvoljan broj korisnika i izdavača.

**NAPOMENA:** Radi se o projektu koji se realizira na Univerzitetu u Sarajevu, Elektrotehnički
fakultet, Odsjek za telekomunikacije.

## Funcionalnosti protokola
🟢 razlikovanje dva tipa korisnika: **izdavače** (autore sadržaja) i **pretplatnike** (korisnike koji konzumiraju sadržaj)<br>
🟢 registracija korisnika na server pomoću URI-a (jedinstvenog alfanumeričkog identifikatora)<br>
🟢 izdavač može objaviti digitalni sadržaj (tekstualni, video, audio, interaktivni) uz definisanje cijene pristupa<br>
🟢 svaki korisnik može pregledati listu dostupnih sadržaja po kategorijama (npr. obrazovni, zabavni, tehnički)<br>
   🟢 model pretplate: mjesečna pretplata na sadržaje određenog izdavača, <br>
   🟢 model pretplate: jednokratna kupovina pojedinačnog sadržaja,<br>
   🔴 model pretplate: grupna pretplata za više korisnika (porodični, akademski paket) **(NIJE IMPLEMENTIRANO)**<br>
🟢 izdavači mogu ažurirati cijene i statuse svojih sadržaja<br>
   🟢 centralni server vodi registar: svih objavljenih sadržaja,<br>
   🟢 centralni server vodi registar: aktivnih pretplata i transakcija,<br>
   🟢 centralni server vodi registar: svih korisničkih naloga i statusa pretplate<br>
🔴 uspostavljen sistem popusta na osnovu broja kupljenih sadržaja ili dužine pretplate (npr. 20% popusta nakon 10 kupljenih sadržaja) **(NIJE IMPLEMENTIRANO)**<br>
🟢 pretplatnici mogu ocjenjivati sadržaje i davati komentare (uz moderaciju od strane izdavača)<br>
🔴 implementiran regionalni sistem sa najmanje dva servera (npr. evropski i američki region) i omogućiti replikaciju i sinhronizaciju sadržaja između regiona **(NIJE IMPLEMENTIRANO)**<br>
🟢 sva signalizacija između klijenata i izdavača mora ići isključivo preko servera<br>

## Instalacija dependency-ja
Za instalaciju Boost.Asio biblioteke Ubuntu/Debian sistemu:
```
sudo apt update
sudo apt-get install libboost-all-dev
```
Boost.Asio se može kombinovati sa JSON bibliotekama kao što su nlohmann/json za obradu JSON podataka. Kako bi se omogućila podrška za JSON format podataka potrebno je JSON biblioteku pohraniti u direktorij *include*.
```
cd include
mkdir json
cd json
curl https://raw.githubusercontent.com/nlohmann/json/develop/single_include/nlohmann/json.hpp>json.h
chmod 777 json.h
```
Sa ciljem realizacije pohrane podataka korištena je SQLITE3 baza podataka. Neophodno je konfigursati Asio okruženje za podršku SQLITE3 bazi podataka. Koraci za instalaciju i konfiguraciju SQLITE3 baze podataka su:
1. Instalacija sqlite3 biblioteke
```
apt-get install sqlite3 libsqlite3-dev
```
2. U root direktoriju Asio okruženja otvoriti direktorij *include* te kreirati direktorij *sqlite3*
3. U direktoriju *include/sqlite3* izvršiti komandu za korištenje alata *SQlite3 Wrapper* sa ciljem lakšeg upravljanja bazom  
```
curl https://raw.githubusercontent.com/mickeyze/sqlite3_wrapper_c-11/refs/heads/master/include/sqlite3_wrapper/sqlite3_wrapper.h>sqlite3_wrapper.h
```
Postojeće okruženje je nadograđeno sa podrškom za uspostavu sigurne TLS/SSL konekcije. Za integraciju TLS/SSL komunikacije u Asio okruženju potrebno je instalirati neophodne biblioteke
```
apt-get install libssl-dev
```
Za instalaciju OpenSSL-a, verzija 3.5.0 korištena je skripta *openssl_3_5_0_install.sh* dostupna na repozitoriju. 
```
chmod +x openssl_3_5_0_install.sh
./openssl_3_5_0_install.sh
```
Nakon uspješne instalacije OpenSSL-a 3.5, može se provjeriti lista podržanih key-enkapsulacijskih mehanizama (KEM). KEM se koriste za sigurnu razmjenu zajedničkog tajnog ključa između klijenta i servera (korištena je kombinacija X25519MLKEM768) dok se digitalni potpisni algoritmi koriste za autentifikaciju i provjeru identiteta i integriteta poruka. Za digitalne potpise koristi se ML-DSA-44 što omogućava praktičnu demonstraciju PQC TLS-a.

Generisanje privatnog ML-DSA-44 ključa:
```
openssl genpkey -algorithm ml-dsa-44 -out server-key.pem
```
Generisanje samopotpisanog certifikata:
```
openssl req -new -x509 -key server-key.pem -out server-cert.pem -days 365 -subj "/C=BA/ST=Sarajevo/L=Sarajevo/O=SDP.etf/OU=IT/CN=localhost" -sha256
```

## Uputstvo za pokretanje
Nakon instalacije potrebnih dependency-ja, potrebno je kompajlirati izvorni kod u izvršne datoteke. Terminal pokrenuti u projektnom direktoriju.

Kompajliranje server.cpp:
```
g++ -std=c++17 -O2 server.cpp -o server -I../asio/include -lboost_system -lssl -lcrypto -lsqlite3
```
Kompajliranje client.cpp:
```
g++ -std=c++17 -O2 client.cpp -o client -I../asio/include -lboost_system -lssl -lcrypto -lsqlite3
```
Kompajliranje test.cpp:
```
g++ -std=c++17 -O2 test.cpp -o test -I../asio/include -lboost_system -lssl -lcrypto -lsqlite3
```
Pokretanje izvršne server datoteke vrši se sljedećom komandom:
```
./server <ip> <port> <dbname>
Primjer: ./server 0.0.0.0 1111 content.db
```
Pokretanje izvršne client datoteke vrši se sljedećom komandom:
```
./client <serverip> <serverport>
Primjer sa lokalne mašine: ./client 0.0.0.0 1111
Primjer sa remote mašine: ./client 100.100.129.2 1111
```
Pokretanje izvršne test datoteke vrši se na dva načina, ovisno o tome želimo li provesti testiranje na već pokrenutom serveru, ili pokretavši specijalne servere za potrebe testiranja. Ukoliko pokrećemo test bez pretpostavke o prethodno pokrenutim serverima, dovoljno je pozvati sljedeću komandu:
```
./test --log_level=nothing --report_level=detailed
```
U slučaju da želimo provesti testiranje na već pokrenutom serveru na 0.0.0.0:1111, to činimo sljedećom komandom:
```
SPAWN_SERVER=0 HOST=0.0.0.0 PORT=1111 ./test --log_level=nothing --report_level=detailed
```

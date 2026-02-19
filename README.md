# Protokol-za-razmjenu-i-naplatu-digitalnih-sadrzaja

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
   🟢 model pretplate: mjesečna pretplata na sadržaje odredenog izdavača, <br>
   🟢 model pretplate: jednokratna kupovina pojedinačnog sadržaja,<br>
   🔴 model pretplate: grupna pretplata za više korisnika (porodični, akademski paket) **(NIJE IMPLEMENTIRANO)**<br>
🟢 izdavači mogu ažurirati cijene i statuse svojih sadržaja<br>
   🟢 centralni server vodi registar: svih objavljenih sadržaja,<br>
   🟢 centralni server vodi registar: aktivnih pretplata i transakcija,<br>
   🟢 centralni server vodi registar: svih korisničkih naloga i statusa pretplate<br>
🔴 uspostavljen sistem popusta na osnovu broja kupljenih sadržaja ili dužine pretplate (npr. 20% popusta nakon 10 kupljenih sadržaja) **(NIJE IMPLEMENTIRANO)**<br>
🟢 pretplatnici mogu ocjenjivati sadržaje i davati komentare (uz moderaciju od strane izdavača)<br>
🔴 implementiran regionalni sistem sa najmanje dva servera (npr. evropski i američki region) i omogućiti replikaciju i sinhronizaciju sadržaja izmedu regiona **(NIJE IMPLEMENTIRANO)**<br>
🟢 sva signalizacija izmedu klijenata i izdavača mora ići isključivo preko servera<br>

## Instalacija dependency-ja

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
Primjer sa remote mašine (pod pretpostavkom da je ip adresa servera 100.100.129.2): ./client 100.100.129.2 1111
```
Pokretanje izvršne test datoteke vrši se na dva načina, ovisno o tome želimo li provesti testiranje na već pokrenutom serveru, ili pokretavši specijalne servere za potrebe testiranja. Ukoliko pokrećemo test bez pretpostavke o prethodno pokrenutim serverima, dovoljno je pozvati sljedeću komandu:
```
./test
```
U slučaju da želimo provesti testiranje na već pokrenutom serveru na 0.0.0.0:1111, to činimo sljedećom komandom:
```
./test
```

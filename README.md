# Protokol-za-razmjenu-i-naplatu-digitalnih-sadrzaja

Cilj ovog projekta je dizajnirati i implementirati protokol za razmjenu i naplatu digitalnih sadržaja u okviru mreže
izdavača i pretplatnika. Protokol se sastoji iz dva dijela: server za distribuciju sadržaja i
klijentskih aplikacija korisnika. Server treba da podrži proizvoljan broj korisnika i izdavača.

**NAPOMENA:** Radi se o projektu koji se realizira na Univerzitetu u Sarajevu, Elektrotehnički
fakultet, Odsjek za telekomunikacije.

## Funcionalnosti protokola
- razlikovanje dva tipa korisnika: **izdavače** (autore sadržaja) i **pretplatnike** (korisnike koji konzumiraju sadržaj)
- registracija korisnika na server pomoću URI-a (jedinstvenog alfanumeričkog identifikatora)
- izdavač može objaviti digitalni sadržaj (tekstualni, video, audio, interaktivni) uz definisanje cijene pristupa
- svaki korisnik može pregledati listu dostupnih sadržaja po kategorijama (npr. obrazovni, zabavni, tehnički)
- sistem pretplate na osnovu različitih modela:
   - mjesečna pretplata na sadržaje odredenog izdavača,
   - jednokratna kupovina pojedinačnog sadržaja,
   - grupna pretplata za više korisnika (porodični, akademski paket)
- izdavači mogu ažurirati cijene i statuse svojih sadržaja
- centralni server vodi registar:
   - svih objavljenih sadržaja,
   - aktivnih pretplata i transakcija,
   - svih korisničkih naloga i statusa pretplate
- uspostavljen sistem popusta na osnovu broja kupljenih sadržaja ili dužine pretplate (npr. 20% popusta nakon 10 kupljenih sadržaja)
- pretplatnici mogu ocjenjivati sadržaje i davati komentare (uz moderaciju od strane izdavača)
- implementiran regionalni sistem sa najmanje dva servera (npr. evropski i američki region) i omogućiti replikaciju i sinhronizaciju sadržaja izmedu regiona
- sva signalizacija izmedu klijenata i izdavača mora ići isključivo preko servera

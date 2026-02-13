# Protokol-za-razmjenu-i-naplatu-digitalnih-sadrzaja

Cilj ovog projekta je dizajnirati i implementirati protokol za razmjenu i naplatu digitalnih sadržaja u okviru mreže
izdavača i pretplatnika. Protokol se sastoji iz dva dijela: server za distribuciju sadržaja i
klijentskih aplikacija korisnika. Server treba da podrži proizvoljan broj korisnika i izdavača.

## Funcionalnosti protokola
razlikovati dva tipa korisnika: izdavaˇce (autore sadrˇzaja) i pretplatnike (korisnike koji
konzumiraju sadrˇzaj);
• registraciju korisnika na server pomo´cu URI-a (jedinstvenog alfanumeriˇckog identifikatora);
• izdavaˇc moˇze objaviti digitalni sadrˇzaj (tekstualni, video, audio, interaktivni) uz definisanje cijene pristupa;
• svaki korisnik moˇze pregledati listu dostupnih sadrˇzaja po kategorijama (npr. obrazovni, zabavni, tehniˇcki);
• implementirati sistem pretplate na osnovu razliˇcitih modela:
– mjeseˇcna pretplata na sadrˇzaje odredenog izdavaˇca,
– jednokratna kupovina pojedinaˇcnog sadrˇzaja,
– grupna pretplata za viˇse korisnika (porodiˇcni, akademski paket).
• izdavaˇci mogu aˇzurirati cijene i statuse svojih sadrˇzaja;
• centralni server vodi registar:
– svih objavljenih sadrˇzaja,
– aktivnih pretplata i transakcija,
– svih korisniˇckih naloga i statusa pretplate.
• uspostaviti sistem popusta na osnovu broja kupljenih sadrˇzaja ili duˇzine pretplate (npr.
20% popusta nakon 10 kupljenih sadrˇzaja);
• pretplatnici mogu ocjenjivati sadrˇzaje i davati komentare (uz moderaciju od strane
izdavaˇca);
• implementirati regionalni sistem sa najmanje dva servera (npr. evropski i ameriˇcki
region) i omogu´citi replikaciju i sinhronizaciju sadrˇzaja izmedu regiona;
• sva signalizacija izmedu klijenata i izdavaˇca mora i´ci iskljuˇcivo preko servera.

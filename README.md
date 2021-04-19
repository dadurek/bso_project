# BSO projekt

## Temat

Tematem projektu jest `Badanie rozwiązań chroniących natywne aplikacje działająwce w trybie użytkownika`.

## Struktura

W repozytorium znajdują sie katalogi o nazwie adekwatnej do opisywanego rozwiązania. W każdym katalogu znajdują sie conajmniej:

* `solution.md` - plik opisujący badaną technikę oraz opis działania exploitu
* `vuln.c` - kod napisany w języku C zawierający podatność bez włączonego zabezpieczenia
* `exploit.py` - exploit napisany w jezyku Python exploitujący aplikację `vuln`
* `vuln-protected.c` - kod napisany w języku C zawierający podatność lecz z włączonym zabezpieczeniem
* `exploiti-protected.py` - exploit napisany w jezyku Python exploitujący aplikację `vuln-protected`

## *solution.md*

W każdym `solution.md` znajduje się:

* opis metody
* omówienie wad i zalet oraz uzyteczności danej techniki ochrony aplikacy natywnych
* porównanie metody dla kompilatorów `gcc` oraz `clang`
* porównanie metody w systemach z rodziny Linux oraz Windows - w metodach, w których taki podział ma znaczenie
* przykład aplikacji oraz atak na aplikację przy wyłączonym zabezpieczeniu
* atak na aplikacje przy włączonym zabezpieczeniu


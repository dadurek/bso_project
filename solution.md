## Atak na aplikacje natywne, przed kórymi obecne metody nie choronią

Takimi atakmi są z pewnością ataki `side-channel attack`. Ataki takie bazują na informacjach zgromadzonych poprzez monitorowanie, odkrywanie lub disasseble systemów komputerowych. Ataki takie nie opierają się na słabościach programu, podatnościach i bugach tak jak ma to miejsce we wszytskich atakach opisanych przeze mnie. Można wyróżnić parę klas ataków:
* `Cache attack` - ataki bazujące na monitorowaniu i analizowaniu pamięci podręczej 
* `Timing attack` - ataki bazujące na mierzeniu czasu różnych operacji wykonywanych przez dany system
* `Power-monitoring attack` - ataki bazujące na pomiarze poboru prąu przez hardware podczas obliczeń
* `Electromagnetic attack` - ataki bazujące na promieniowaniu elektromagnetycznym, który może być źródłem informacji
* `Acoustic cryptanalysis` - ataki opierające się na analizie dźwięku
* `Differential fault analysis` - atak mający na celu analizowanie zachowania systemu na podawanie błednych danych powodująych błędy
* `Data remanence` - odczytanie danych, które powinny być usunięte


Najciekawszym sposobem na expoitację systemu może być atak typu `power-analysis attack`. Rozróżnialne są tutaj dwa rodzaje: simple power analysis (SPA) oraz differential power analysis (DPA). 

Załóżmy że istnieje program, który szyfruje jakieś pliki. Dzięki pomiarom napięcia pobieranym przez procesor oraz poprzez analizowanie danych często jesteśmy w stanie wyczytać z nich pewne dane - najczęściej jest to sekretny klucz. Oczywiście nie jest to proces tak prosty, należy pamiętać o szumie który wystepuje, a także o tym że jest to zadanie czasochłonne. Jest to jednak na pewno szybsze rowiązanie niż atak siłowy na klucz i próbowanie wszytskich kombinacji. W celu ochrony przed atakami typu DPA rekomendowane jest nieużywanie ciągle tego samego klucza, lecz generowanie za każdym razem nowego klucza z poprzedniego. Oznacza to, że wartości klucza będą ciągle zmienne.

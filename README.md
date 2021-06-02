# GOST R 34.12-2015 Magma

## Описание

Реализован базовый шифр Магма из ГОСТ Р 34.12-2015 и режим выработки имитовставки из ГОСТ Р 34.13-2015.

 ## Установка

 Для полноценной работы достаточно подключить исходные фаилы себе в программу, либо скомпилировать программу-пример с помощью программы gcc:
 ```bash
 gcc Example_Programm.c -o Magma.exe
 ```

 ## Тесты

 Чтобы запустить тесты нужно установить [gtests](https://github.com/google/googletest). 

 ### Краткая инструкция по установке и компиляции 
 Скачиваем этот [раздел](https://github.com/google/googletest/tree/master/googletest), и выполняем следующие действия в папке с gtests:
 ```bash
 mkdir build
 cd build
 cmake ..
 echo "CXX_FLAGS += -std=c++11" >> CMakeFiles/gtest_main.dir/flags.make
 echo "CXX_FLAGS += -std=c++11" >> CMakeFiles/gtest.dir/flags.make
 make
 ```
 Для компиляции используются следующие команды:
 ```bash
 g++ -std=c++11 -pthread -I<путь до папки include> -c -o prog.o tests.c
 g++ -o gtest.exe prog.o -L<путь до папки build/lib> -lgtest -pthread
 ```

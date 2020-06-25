# Утилита traceroute 

Версия 1.3

Автор: Пелевина Анастасия (pelevina.2000@mail.ru)

## Описание

Приложение является реализацией утилиты __traceroute__

## Состав

Консольная версия: `main.py`

## Консольная версия

Запуск: `main.py [-h] [-n] [-q PACKETS] [-w WAIT] [-z PAUSE] [-m HOPS]
                     [-s START]
                     host`

__Позиционные аргументы:__

  * `host` - адрес в формате имени хоста или IP-адреса

__Опциональные аргументы:__

  * `-h, --help` - вывод справки
  * `-n, --numerically` - выводить только IP-адреса узлов
  * `-q PACKETS, --query PACKETS` - количество запросов на один ttl
  * `-w WAIT, --wait WAIT` - максимальное время ожидание получения ответа
  * `-z PAUSE` - задержка между зарпосами
  * `-m HOPS, --max HOPS` - максимальный ttl
  * `-s START, --start START` - первое значение ttl

## Настройка работы для Windows
Инструкция на примере интерфейса Windows 7. Настройка на других версиях Windows происходит 
аналогичным образом
1. Откройте Брандмауэр Windows и выберите в меню слева "Дополнительные параметры"
    * ![1](https://i.imgur.com/MoZljYP.jpg)
2. Для входящих соединений создайте новое правило брандмауэра __(Тип правила - настраиваемое)__
    * ![2](https://i.imgur.com/2QXBFmq.jpg) 
3. В протоколах и портах выберите протокол _ICMPv4_
    * ![3](https://i.imgur.com/W24kdqn.jpg)
4. Сохраните новое правило и не забудьте разрешить Брандмаэру внешние подключения из списка правил

## Подробности реализации

На данный момент в проекте присутствует основной файл `main.py` и пакет `logic` с модулями, реализующими
логику приложения: `logic.traceroute.py`, `logic.utils.py` и `logic.network_utils.py`.
В первом находится класс `Traceroute`, с методами для исполнения основного алгоритмa трассровки.

Во втором модуле находятся различные вспомогательные статические методы: вычисление чексуммы,
создание сокета для отправки/получения пакетов, создание пакета, 
вывод результата отправления одного пакета и тд. 

В третьем вспомогательные методы для работы с сетью/сокетами: создание сокета с необходимыми 
настройками.

Тестами покрыты модули `logic.traceroute.py` и `logic.utils.py`, тесты 
находятся в директории `tests` в файлах с соответствующими названиями. 
Покрытие тестами составляет _82%_:

         Stmts / Miss / Cover
         ------/------/------
         274   / 50   / 82%

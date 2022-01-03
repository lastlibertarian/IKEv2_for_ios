# VPN IKEv2 + скрипт для IOS
### Простая и быстрая установка VPN соединения
___

#### Требования:
+ Сервер Ubuntu 20.04
___
## Шаг 1.
### Настройка на стороне сервера
Качаем проект:
```sh
git clone https://github.com/lastlibertarian/IKEv2_for_ios /root/IKEv2_for_ios
```
Запускаем скрипт:
```sh
python3 /root/IKEv2_for_ios/main.py
```
Вводим имя соединения:
```buildoutcfg
Enter login for your vpn
>>> Имя соединения ↵
```
После завершения получаем результат:

```buildoutcfg
Данные для подключения:
ip - 313.172.626.1
login - VPNclient
password - 4M7xleu8Wvm3/Fb2fSoJGBuk1jM3Jl
сертификат - /etc/ipsec.d/cacerts/ca-cert.pem
файл для IOS - /root/VPNclient.mobileconfig
```
___
## Шаг 2.
### Настройка на стороне клиента

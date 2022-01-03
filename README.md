# VPN IKEv2 + скрипт для IOS
### Простая и быстрая установка VPN соединения
___

#### Требования:
+ Сервер Ubuntu 20.04
___
## Шаг 1.
### Настройка на стороне сервера
Качаем проект:
```shell
git clone https://github.com/lastlibertarian/IKEv2_for_ios /root/IKEv2_for_ios
```
Запускаем скрипт:
```shell
python3 /root/IKEv2_for_ios/main.py
```
Вводим имя соединения:
```buildoutcfg
Enter login for your vpn
>>> Имя соединения ↵
```
После завершения получаем результат:


>*Данные для подключения:*<br> 
`ip - 313.172.626.1`<br> 
`login - VPNclient`<br> 
`password - 4M7xleu8Wvm3/Fb2fSoJGBuk1jM3Jl`<br> 
`сертификат - /etc/ipsec.d/cacerts/ca-cert.pem`<br> 
`файл для IOS - /root/VPNclient.mobileconfig
`
> 
Удаляем проект:
```shell
rm -r /root/IKEv2_for_ios/
```
___
## Шаг 2.
### Настройка на стороне клиента
1. ###macOS
    + Качаем сертификат с помощью `scp` либо открываем с помощью `cat /etc/ipsec.d/cacerts/ca-cert.pem`
   



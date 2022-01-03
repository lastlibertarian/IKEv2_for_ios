# VPN IKEv2 + скрипт для IOS

### Простая и быстрая установка VPN соединения
**_Помимо простоты установки скрипт создаст конфиг для IOS<br>
Вот несколько плюсов:_**
+ [x] Нет необходимости в сторонних приложениях, конфиг "вшивается" и работает в IOS
+ [x] Работает постоянно не отключаясь
+ [x] Не высаживает аккумулятор

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


> *Данные для подключения:*<br>
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

### macOS

+ Качаем сертификат с помощью `scp` либо открываем с помощью `cat /etc/ipsec.d/cacerts/ca-cert.pem`
+ Меняем разрешение на `.crt`
+ Кликаем на сертификат, подтверждаем его добавление в Связку Ключей, введя пароль.
+ Открываем Связку Ключей, находим VPN(имя соединения) и задаем нужные разрешения. Дважды кликаем по нему, раскрываем
  раздел «Доверие» (Trust) и выбираем «Всегда доверять» (Always Trust).
+ Переходим в настройки сети. Нажимаем плюсик внизу, выбираем VPN, IKEv2 и жмем «Создать» (Create), вписываем IP сервера
  в строки «Адрес сервера» и «Удаленный ID».
+ В настройках аутентификации выбираем «Имя пользователя» и указываем свои логин и пароль. Пароль, если что можно найти
  на сервере `cat /etc/ipsec.secrets`

### Windows

+ Консоль управления → Файл → Добавить или удалить оснастку → Сертификаты → Добавить
+ Учетная запись компьютера → Далее → Локальный компьютер → Закончить
+ В «Корне консоли» выбираем «Доверенные корневые центры сертификации для доверия федерации» и «Сертификаты».
+ В меню «Действия» в правой панели нажимаем «Все задачи» и «Импортировать».
+ Вызываем меню выбора файла, выставь тип X.509 и импортируем свой сертификат.
+ Панель управления → Сеть интернет → VPN → вписываем адрес сервера, логин и пароль.

### IOS

+ Открываем конфиг на сервере `cat /root/VPNclient.mobileconfig`
+ Копируем, сохраняем в блокноте. Обязательно оставляем расширение `.mobileconfig`
+ Отправляем любым удобным для вас способом на iphone, сохраняем в Файлы
+ Нажимаем на файл, появится сообщение «Профиль загружен»
+ Настройки → Основные → VPN и управление устройством → VPN Configuration
+ Нажимаем Установить, вводим ПИН
+ Можно подписать сертификат в Настройки → Основные → Об этом устройстве → Доверие сертификатам. но работать будет
  одинаково как с подписанным так и не с подписанным

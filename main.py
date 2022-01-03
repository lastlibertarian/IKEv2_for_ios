import os
from scripts.scripts import *

os.system('clear')
login = input('Enter login for your vpn\n>>> ')
password = os.popen("openssl rand -base64 24").read().rstrip()[:-2]
ip = os.popen("ip route get 1.2.3.4 | awk '{print $7}'").read().rstrip()
interface = os.popen("ip route get 1.2.3.4 | awk '{print $5}'").read().rstrip()
uuid_1 = os.popen("uuidgen").read().rstrip()
uuid_2 = os.popen("uuidgen").read().rstrip()
uuid_3 = os.popen("uuidgen").read().rstrip()
uuid_4 = os.popen("uuidgen").read().rstrip()

os.system('echo Устанавливаю strongswan && apt update && apt install strongswan strongswan-pki \
  libcharon-extra-plugins libcharon-extauth-plugins \
  libstrongswan-extra-plugins libtss2-tcti-tabrmd-dev -y && echo [+]')

os.system('mkdir ~/pki && mkdir ~/pki/cacerts && mkdir ~/pki/certs && mkdir ~/pki/private && chmod 700 ~/pki')

os.system(
    'echo Гeнерирую корневой ключ RSA и корневой сертификат && pki --gen --type rsa --size 4096 --outform pem >'
    ' ~/pki/private/ca-key.pem && '
    f'pki --self --ca --lifetime 3650 --in ~/pki/private/ca-key.pem --type rsa \
  --dn "CN=VPN {login}" --outform pem > ~/pki/cacerts/ca-cert.pem && echo [+]')

os.system('echo Создаю приватный ключ && pki --gen --type rsa --size 4096 --outform pem > ~/pki/private/server-key.pem '
          '&& echo [+]')

print('[+]\nСоздаю сертификат')
os.system(f'pki --pub --in ~/pki/private/server-key.pem --type rsa | pki --issue --lifetime 1825 \
  --cacert ~/pki/cacerts/ca-cert.pem --cakey ~/pki/private/ca-key.pem \
  --dn "CN={ip}" --san @{ip} --san {ip} \
  --flag serverAuth --flag ikeIntermediate --outform pem \
  > ~/pki/certs/server-cert.pem')

os.system(f'echo Настраиваю туннель IKEv2 && echo "{ipsec_conf.format(ip=ip)}"> /etc/ipsec.conf && echo [+] && '
          f'echo "{ipsec_secrets.format(login=login, password=password)}" > /etc/ipsec.secrets && systemctl restart '
          f'strongswan-starter')

os.system('echo Настраиваю сеть && ufw allow OpenSSH && echo "y" | sudo ufw enable && ufw allow 500,4500/udp')

os.system(f'echo "{before_rules.format(interface=interface)}" > /etc/ufw/before.rules && echo "{sysctl_conf}" > '
          f'/etc/ufw/sysctl.conf && ufw disable && echo "y" | sudo ufw enable')

with open('/etc/ipsec.d/cacerts/ca-cert.pem', 'r') as file:
    certificate = ''.join([f'\t{line}' for line in file.readlines()[1:-1]])

os.system(
    f'echo'
    f' "{mobile_config.format(certificate=certificate, uuid_1=uuid_1, login=login, uuid_2=uuid_2, ip=ip, password=password, uuid_3=uuid_3, uuid_4=uuid_4)}" '
    f'> {login}.mobileconfig')

print(f'[+]\n\n\nДанные для подключения:\nip - {ip}\nlogin - {login}\npassword - {password}\nсертификат - '
      f'/etc/ipsec.d/cacerts/ca-cert.pem\nфайл для IOS - /root/{login}.mobileconfig\n\n')

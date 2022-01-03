import os

os.system('clear')
login = input('Enter login for your vpn\n>>> ')
password = os.popen("openssl rand -base64 24").read().rstrip()[:-2]
ip = os.popen("ip route get 1.2.3.4 | awk '{print $7}'").read().rstrip()
interface = os.popen("ip route get 1.2.3.4 | awk '{print $5}'").read().rstrip()
uuid_1 = os.popen("uuidgen").read().rstrip()
uuid_2 = os.popen("uuidgen").read().rstrip()
uuid_3 = os.popen("uuidgen").read().rstrip()
uuid_4 = os.popen("uuidgen").read().rstrip()
crt = list()

print('Устанавливаю strongswan')
os.system('apt update && apt install strongswan strongswan-pki \
  libcharon-extra-plugins libcharon-extauth-plugins \
  libstrongswan-extra-plugins libtss2-tcti-tabrmd-dev -y')
print('[+]')
os.system('mkdir ~/pki && mkdir ~/pki/cacerts && mkdir ~/pki/certs && mkdir ~/pki/private && chmod 700 ~/pki')
print('Гeнерирую корневой ключ RSA и корневой сертификат')
os.system('pki --gen --type rsa --size 4096 --outform pem > ~/pki/private/ca-key.pem && '
          f'pki --self --ca --lifetime 3650 --in ~/pki/private/ca-key.pem --type rsa \
  --dn "CN=VPN {login}" --outform pem > ~/pki/cacerts/ca-cert.pem')
print('[+]\nСоздаю приватный ключ')
os.system('pki --gen --type rsa --size 4096 --outform pem > ~/pki/private/server-key.pem')
print('[+]\nСоздаю сертификат')
os.system(f'pki --pub --in ~/pki/private/server-key.pem --type rsa | pki --issue --lifetime 1825 \
  --cacert ~/pki/cacerts/ca-cert.pem --cakey ~/pki/private/ca-key.pem \
  --dn "CN={ip}" --san @{ip} --san {ip} \
  --flag serverAuth --flag ikeIntermediate --outform pem \
  > ~/pki/certs/server-cert.pem')
print('[+]')
os.system('cp -r ~/pki/* /etc/ipsec.d/')
print('Настраиваю туннель IKEv2')
os.system('echo '
          '"config setup\n  charondebug=\\"ike 1, knl 1, cfg 0\\"\n  uniqueids=no\n'
          'conn ikev2-vpn\n  auto=add\n  compress=no\n  type=tunnel\n  keyexchange=ikev2\n  fragmentation=yes\n  '
          f'forceencaps=yes\n  dpdaction=clear\n  dpddelay=300s\n  rekey=no\n  left=%any\n  leftid={ip}\n  '
          'leftcert=server-cert.pem\n  leftsendcert=always\n  leftsubnet=0.0.0.0/0\n  right=%any\n  rightid=%any\n  '
          'rightauth=eap-mschapv2\n  rightsourceip=10.10.10.0/24\n  rightdns=8.8.8.8,8.8.4.4\n  rightsendcert=never\n'
          '  eap_identity=%identity\n  ike=chacha20poly1305-sha512-curve25519-prfsha512,aes256gcm16-sha384-prfsha384-'
          'ecp384,aes256-sha1-modp1024,aes128-sha1-modp1024,3des-sha1-modp1024!\n'
          '  esp=chacha20poly1305-sha512,aes256gcm16-ecp384,aes256-sha256,aes256-sha1,3des-sha1!\n" '
          '> /etc/ipsec.conf')
print('[+]')
os.system(f'printf ": RSA \\"server-key.pem\\"\n{login} : EAP \\"{password}\\"\n" > /etc/ipsec.secrets')

os.system('systemctl restart strongswan-starter')
print('Настраиваю сеть')
os.system('ufw allow OpenSSH && echo "y" | sudo ufw enable && ufw allow 500,4500/udp')

os.system('perl -i -pe "print \\"-A ufw-before-forward --match policy --pol ipsec --dir in --proto esp -s 10.10.10.0/24'
          ' -j ACCEPT\n'
          '-A ufw-before-forward --match policy --pol ipsec --dir out --proto esp -d 10.10.10.0/24 -j ACCEPT\n'
          '\\" if $. == 17" /etc/ufw/before.rules')

os.system(f'perl -i -pe "print \\"*nat\n-A POSTROUTING -s 10.10.10.0/24 -o {interface} -m policy --pol ipsec --dir out '
          f'-j ACCEPT\n-A POSTROUTING -s 10.10.10.0/24 -o {interface} -j MASQUERADE\n'
          f'COMMIT\n\n*mangle\n-A FORWARD --match policy --pol ipsec --dir in -s 10.10.10.0/24 -o {interface} '
          f'-p tcp -m tcp --tcp-flags SYN,RST SYN -m tcpmss --mss 1361:1536 -j TCPMSS --set-mss 1360\n'
          f'COMMIT\n\\" if $. == 10" /etc/ufw/before.rules')

os.system('echo "net/ipv4/ip_forward=1\nnet/ipv4/conf/all/accept_redirects=0\n'
          'net/ipv4/conf/all/send_redirects=0\nnet/ipv4/ip_no_pmtu_disc=1\n" >> /etc/ufw/sysctl.conf')

os.system('ufw disable && echo "y" | sudo ufw enable')

with open('/etc/ipsec.d/cacerts/ca-cert.pem', 'r') as file:
    for line in file.readlines()[1:-1]:
        crt.append(f'\t{line}')
certificate = ''.join(crt)

script = f'<?xml version="1.0" encoding="UTF-8"?>\n\
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n\
<plist version="1.0">\n\
<dict>\n\
  <key>PayloadContent</key>\n\
  <array>\n\
    <dict>\n\
      <key>PayloadCertificateFileName</key>\n\
      <string>cert.pem</string>\n\
      <key>PayloadContent</key>\n\
      <data>\n\
{certificate}\
      </data>\n\
      <key>PayloadDescription</key>\n\
      <string>Adds a certificate</string>\n\
      <key>PayloadDisplayName</key>\n\
      <string>cert.pem</string>\n\
      <key>PayloadIdentifier</key>\n\
      <string>com.apple.security.pkcs12.{uuid_1}</string>\n\
      <key>PayloadType</key>\n\
      <string>com.apple.security.pem</string>\n\
      <key>PayloadUUID</key>\n\
      <string>{uuid_1}</string>\n\
      <key>PayloadVersion</key>\n\
      <integer>1</integer>\n\
    </dict>\n\
    <dict>\n\
      <key>UserDefinedName</key>\n\
      <string>StrongSwan</string>\n\
      <key>PayloadDisplayName</key>\n\
      <string>{login}</string>\n\
      <key>PayloadIdentifier</key>\n\
      <string>swan.vpn.always</string>\n\
      <key>PayloadUUID</key>\n\
      <string>{uuid_2}</string>\n\
      <key>VPNType</key>\n\
      <string>IKEv2</string>\n\
      <key>IKEv2</key>\n\
      <dict>\n\
        <key>RemoteAddress</key>\n\
        <string>{ip}</string>\n\
        <key>RemoteIdentifier</key>\n\
        <string>{ip}</string>\n\
        <key>LocalIdentifier</key>\n\
        <string></string>\n\
        <key>AuthenticationMethod</key>\n\
        <string>None</string>\n\
        <key>DeadPeerDetectionRate</key>\n\
            <string>Medium</string>\n\
            <key>DisableMOBIKE</key>\n\
            <integer>0</integer>\n\
            <key>DisableRedirect</key>\n\
            <integer>0</integer>\n\
            <key>EnableCertificateRevocationCheck</key>\n\
            <integer>0</integer>\n\
            <key>EnablePFS</key>\n\
            <integer>0</integer>\n\
            <key>ExtendedAuthEnabled</key>\n\
            <true/>\n\
            <key>IKESecurityAssociationParameters</key>\n\
            <dict>\n\
              <key>DiffieHellmanGroup</key>\n\
              <integer>2</integer>\n\
              <key>EncryptionAlgorithm</key>\n\
              <string>3DES</string>\n\
              <key>IntegrityAlgorithm</key>\n\
              <string>SHA1-96</string>\n\
              <key>LifeTimeInMinutes</key>\n\
              <integer>1440</integer>\n\
            </dict>\n\
        <key>AuthName</key>\n\
        <string>{login}</string>\n\
        <key>AuthPassword</key>\n\
        <string>{password}</string>\n\
      </dict>\n\
      <key>OnDemandEnabled</key>\n\
      <integer>1</integer>\n\
      <key>OnDemandRules</key>\n\
      <array>\n\
        <dict>\n\
          <key>Action</key>\n\
          <string>Connect</string>\n\
          <key>InterfaceTypeMatch</key>\n\
          <string>Cellular</string>\n\
        </dict>\n\
        <dict>\n\
          <key>Action</key>\n\
          <string>Connect</string>\n\
          <key>InterfaceTypeMatch</key>\n\
          <string>WiFi</string>\n\
        </dict>\n\
      </array>\n\
      <key>OverridePrimary</key>\n\
      <true/>\n\
      <key>IPv4</key>\n\
      <dict>\n\
        <key>OverridePrimary</key>\n\
        <integer>1</integer>\n\
      </dict>\n\
      <key>PayloadType</key>\n\
      <string>com.apple.vpn.managed</string>\n\
      <key>PayloadVersion</key>\n\
      <integer>1</integer>\n\
    </dict>\n\
  </array>\n\
  <key>PayloadDisplayName</key>\n\
  <string>VPN Configuration</string>\n\
  <key>PayloadIdentifier</key>\n\
  <string>{uuid_3}</string>\n\
  <key>PayloadRemovalDisallowed</key>\n\
  <false/>\n\
  <key>PayloadType</key>\n\
  <string>Configuration</string>\n\
  <key>PayloadUUID</key>\n\
  <string>{uuid_4}</string>\n\
  <key>PayloadVersion</key>\n\
  <integer>1</integer>\n\
</dict>\n\
</plist>\n'

os.system(f'echo "{script}" > {login}.mobileconfig')

print(f'[+]\n\n\nДанные для подключения:\nip - {ip}\nlogin - {login}\npassword - {password}\nсертификат - '
      f'/etc/ipsec.d/cacerts/ca-cert.pem\nфайл для IOS - /root/{login}.mobileconfig\n\n')

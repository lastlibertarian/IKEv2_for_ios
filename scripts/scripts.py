ipsec_conf = 'config setup\n\
  charondebug="ike 1, knl 1, cfg 0"\n\
  uniqueids=no\n\
conn ikev2-vpn\n\
  auto=add\n\
  compress=no\n\
  type=tunnel\n\
  keyexchange=ikev2\n\
  fragmentation=yes\n\
  forceencaps=yes\n\
  dpdaction=clear\n\
  dpddelay=300s\n\
  rekey=no\n\
  left=%any\n\
  leftid={ip}\n\
  leftcert=server-cert.pem\n\
  leftsendcert=always\n\
  leftsubnet=0.0.0.0/0\n\
  right=%any\n\
  rightid=%any\n\
  rightauth=eap-mschapv2\n\
  rightsourceip=10.10.10.0/24\n\
  rightdns=8.8.8.8,8.8.4.4\n\
  rightsendcert=never\n\
  eap_identity=%identity\n\
  ike=chacha20poly1305-sha512-curve25519-prfsha512,aes256gcm16-sha384-prfsha384-ecp384,aes256-sha1-modp1024,' \
             'aes128-sha1-modp1024,3des-sha1-modp1024!\n\
  esp=chacha20poly1305-sha512,aes256gcm16-ecp384,aes256-sha256,aes256-sha1,3des-sha1!'

ipsec_secrets = ': RSA "server-key.pem"\n\
{login} : EAP "{password}"'

before_rules = '#\n\
# rules.before\n\
#\n\
# Rules that should be run before the ufw command line added rules. Custom\n\
# rules should be added to one of these chains:\n\
#   ufw-before-input\n\
#   ufw-before-output\n\
#   ufw-before-forward\n\
#\n\
*nat\n\
-A POSTROUTING -s 10.10.10.0/24 -o {interface} -m policy --pol ipsec --dir out -j ACCEPT\n\
-A POSTROUTING -s 10.10.10.0/24 -o {interface} -j MASQUERADE\n\
COMMIT\n\
*mangle\n\
-A FORWARD --match policy --pol ipsec --dir in -s 10.10.10.0/24 -o {interface} -p tcp -m tcp --tcp-flags SYN,RST SYN -m ' \
               'tcpmss --mss 1361:1536 -j TCPMSS --set-mss 1360\n\
COMMIT\n\
# Don\'t delete these required lines, otherwise there will be errors\n\
*filter\n\
:ufw-before-input - [0:0]\n\
:ufw-before-output - [0:0]\n\
:ufw-before-forward - [0:0]\n\
:ufw-not-local - [0:0]\n\
-A ufw-before-forward --match policy --pol ipsec --dir in --proto esp -s 10.10.10.0/24 -j ACCEPT\n\
-A ufw-before-forward --match policy --pol ipsec --dir out --proto esp -d 10.10.10.0/24 -j ACCEPT\n\
# End required lines\n\n\
# allow all on loopback\n\
-A ufw-before-input -i lo -j ACCEPT\n\
-A ufw-before-output -o lo -j ACCEPT\n\n\
# quickly process packets for which we already have a connection\n\
-A ufw-before-input -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n\
-A ufw-before-output -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n\
-A ufw-before-forward -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n\n\
# drop INVALID packets (logs these in loglevel medium and higher)\n\
-A ufw-before-input -m conntrack --ctstate INVALID -j ufw-logging-deny\n\
-A ufw-before-input -m conntrack --ctstate INVALID -j DROP\n\n\
# ok icmp codes for INPUT\n\
-A ufw-before-input -p icmp --icmp-type destination-unreachable -j ACCEPT\n\
-A ufw-before-input -p icmp --icmp-type time-exceeded -j ACCEPT\n\
-A ufw-before-input -p icmp --icmp-type parameter-problem -j ACCEPT\n\
-A ufw-before-input -p icmp --icmp-type echo-request -j ACCEPT\n\n\
# ok icmp code for FORWARD\n\
-A ufw-before-forward -p icmp --icmp-type destination-unreachable -j ACCEPT\n\
-A ufw-before-forward -p icmp --icmp-type time-exceeded -j ACCEPT\n\
-A ufw-before-forward -p icmp --icmp-type parameter-problem -j ACCEPT\n\
-A ufw-before-forward -p icmp --icmp-type echo-request -j ACCEPT\n\n\
# allow dhcp client to work\n\
-A ufw-before-input -p udp --sport 67 --dport 68 -j ACCEPT\n\n\
#\n\
# ufw-not-local\n\
#\n\
-A ufw-before-input -j ufw-not-local\n\n\
# if LOCAL, RETURN\n\
-A ufw-not-local -m addrtype --dst-type LOCAL -j RETURN\n\n\
# if MULTICAST, RETURN\n\
-A ufw-not-local -m addrtype --dst-type MULTICAST -j RETURN\n\n\
# if BROADCAST, RETURN\n\
-A ufw-not-local -m addrtype --dst-type BROADCAST -j RETURN\n\n\
# all other non-local packets are dropped\n\
-A ufw-not-local -m limit --limit 3/min --limit-burst 10 -j ufw-logging-deny\n\
-A ufw-not-local -j DROP\n\
# allow MULTICAST mDNS for service discovery (be sure the MULTICAST line above\n\
# is uncommented)\n\
-A ufw-before-input -p udp -d 224.0.0.251 --dport 5353 -j ACCEPT\n\n\
# allow MULTICAST UPnP for service discovery (be sure the MULTICAST line above\n\
# is uncommented)\n\
-A ufw-before-input -p udp -d 239.255.255.250 --dport 1900 -j ACCEPT\n\n\
# don\'t delete the \'COMMIT\' line or these rules won\'t be processed\n\
COMMIT'

sysctl_conf = '#\n\
# Configuration file for setting network variables. Please note these settings\n\
# override /etc/sysctl.conf and /etc/sysctl.d. If you prefer to use\n\
# /etc/sysctl.conf, please adjust IPT_SYSCTL in /etc/default/ufw. See\n\
# Documentation/networking/ip-sysctl.txt in the kernel source code for more\n\
# information.\n\
#\n\n\
# Uncomment this to allow this host to route packets between interfaces\n\
#net/ipv4/ip_forward=1\n\
#net/ipv6/conf/default/forwarding=1\n\
#net/ipv6/conf/all/forwarding=1\n\n\
# Disable ICMP redirects. ICMP redirects are rarely used but can be used in\n\
# MITM (man-in-the-middle) attacks. Disabling ICMP may disrupt legitimate\n\
# traffic to those sites.\n\
net/ipv4/conf/all/accept_redirects=0\n\
net/ipv4/conf/default/accept_redirects=0\n\
net/ipv6/conf/all/accept_redirects=0\n\
net/ipv6/conf/default/accept_redirects=0\n\n\
# Ignore bogus ICMP errors\n\
net/ipv4/icmp_echo_ignore_broadcasts=1\n\
net/ipv4/icmp_ignore_bogus_error_responses=1\n\
net/ipv4/icmp_echo_ignore_all=0\n\n\
# Don\'t log Martian Packets (impossible addresses)\n\
# packets\n\
net/ipv4/conf/all/log_martians=0\n\
net/ipv4/conf/default/log_martians=0\n\n\
#net/ipv4/tcp_fin_timeout=30\n\
#net/ipv4/tcp_keepalive_intvl=1800\n\n\
# Uncomment this to turn off ipv6 autoconfiguration\n\
#net/ipv6/conf/default/autoconf=1\n\
#net/ipv6/conf/all/autoconf=1\n\n\
# Uncomment this to enable ipv6 privacy addressing\n\
#net/ipv6/conf/default/use_tempaddr=2\n\
#net/ipv6/conf/all/use_tempaddr=2\n\
net/ipv4/ip_forward=1\n\
net/ipv4/conf/all/accept_redirects=0\n\
net/ipv4/conf/all/send_redirects=0\n\
net/ipv4/ip_no_pmtu_disc=1'

mobile_config = f'<?xml version="1.0" encoding="UTF-8"?>\n\
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
</plist>'
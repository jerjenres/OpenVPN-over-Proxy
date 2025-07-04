#!/bin/bash
#
# https://github.com/Null3rror/openvpn-over-proxy
#
# Copyright (c) 2020 Null3rror. Released under the MIT License.


# Detect Debian users running the script with "sh" instead of bash
if readlink /proc/$$/exe | grep -q "dash"; then
	echo 'This installer needs to be run with "bash", not "sh".'
	exit
fi

# Discard stdin. Needed when running from an one-liner which includes a newline
read -N 999999 -t 0.001

# Detect OpenVZ 6
if [[ $(uname -r | cut -d "." -f 1) -eq 2 ]]; then
	echo "The system is running an old kernel, which is incompatible with this installer."
	exit
fi

# Detect OS
# $os_version variables aren't always in use, but are kept here for convenience
if grep -qs "ubuntu" /etc/os-release; then
	os="ubuntu"
	os_version=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
	group_name="nogroup"
elif [[ -e /etc/debian_version ]]; then
	os="debian"
	os_version=$(grep -oE '[0-9]+' /etc/debian_version | head -1)
	group_name="nogroup"
elif [[ -e /etc/centos-release ]]; then
	os="centos"
	os_version=$(grep -oE '[0-9]+' /etc/centos-release | head -1)
	group_name="nobody"
elif [[ -e /etc/fedora-release ]]; then
	os="fedora"
	os_version=$(grep -oE '[0-9]+' /etc/fedora-release | head -1)
	group_name="nobody"
else
	echo "This installer seems to be running on an unsupported distribution.
Supported distributions are Ubuntu, Debian, CentOS, and Fedora."
	exit
fi

if [[ "$os" == "ubuntu" && "$os_version" -lt 1804 ]]; then
	echo "Ubuntu 18.04 or higher is required to use this installer.
This version of Ubuntu is too old and unsupported."
	exit
fi

if [[ "$os" == "debian" && "$os_version" -lt 9 ]]; then
	echo "Debian 9 or higher is required to use this installer.
This version of Debian is too old and unsupported."
	exit
fi

if [[ "$os" == "centos" && "$os_version" -lt 7 ]]; then
	echo "CentOS 7 or higher is required to use this installer.
This version of CentOS is too old and unsupported."
	exit
fi

# Detect environments where $PATH does not include the sbin directories
if ! grep -q sbin <<< "$PATH"; then
	echo '$PATH does not include sbin. Try using "su -" instead of "su".'
	exit
fi

if [[ "$EUID" -ne 0 ]]; then
	echo "This installer needs to be run with superuser privileges."
	exit
fi

if [[ ! -e /dev/net/tun ]] || ! ( exec 7<>/dev/net/tun ) 2>/dev/null; then
	echo "The system does not have the TUN device available.
TUN needs to be enabled before running this installer."
	exit
fi

new_client () {
	# Generates the custom client.ovpn
	{
	cat /etc/openvpn/server/client-common.txt
	echo "<ca>"
	cat /etc/openvpn/server/easy-rsa/pki/ca.crt
	echo "</ca>"

	echo "<auth-user-pass>"
	echo "$vpn_user"
	echo "$vpn_password"
	echo "</auth-user-pass>"
	} > ~/"$client".ovpn
}

ipvalid() {
  # Set up local variables
  local ipv4=${1:-1.2.3.4}
  local IFS=.; local -a a=($ipv4)
  # Start with a regex format test
  [[ $ipv4 =~ ^[0-9]+(\.[0-9]+){3}$ ]] || return 1
  # Test values of quads
  local quad
  for quad in {0..3}; do
    [[ "${a[$quad]}" -gt 255 ]] && return 1
  done
  return 0
}


if [[ ! -e /etc/openvpn/server/server.conf ]]; then
	clear
	echo 'Welcome to this OpenVPN over Proxy road warrior installer!'
	# If system has a single IPv4, it is selected automatically. Else, ask the user
	if [[ $(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}') -eq 1 ]]; then
		ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')
	else
		number_of_ip=$(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}')
		echo
		echo "Which IPv4 address should be used?"
		ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | nl -s ') '
		read -p "IPv4 address [1]: " ip_number
		until [[ -z "$ip_number" || "$ip_number" =~ ^[0-9]+$ && "$ip_number" -le "$number_of_ip" ]]; do
			echo "$ip_number: invalid selection."
			read -p "IPv4 address [1]: " ip_number
		done
		[[ -z "$ip_number" ]] && ip_number="1"
		ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sed -n "$ip_number"p)
	fi
	# If $ip is a private IP address, the server must be behind NAT
	if echo "$ip" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
		echo
		echo "This server is behind NAT. What is the public IPv4 address or hostname?"
		# Get public IP and sanitize with grep
		get_public_ip=$(grep -m 1 -oE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' <<< "$(wget -T 10 -t 1 -4qO- "http://ip1.dynupdate.no-ip.com/" || curl -m 10 -4Ls "http://ip1.dynupdate.no-ip.com/")")
		read -p "Public IPv4 address / hostname [$get_public_ip]: " public_ip
		# If the checkip service is unavailable and user didn't provide input, ask again
		until [[ -n "$get_public_ip" || -n "$public_ip" ]]; do
			echo "Invalid input."
			read -p "Public IPv4 address / hostname: " public_ip
		done
		[[ -z "$public_ip" ]] && public_ip="$get_public_ip"
	fi
	# If system has a single IPv6, it is selected automatically
	if [[ $(ip -6 addr | grep -c 'inet6 [23]') -eq 1 ]]; then
		ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}')
	fi
	# If system has multiple IPv6, ask the user to select one
	if [[ $(ip -6 addr | grep -c 'inet6 [23]') -gt 1 ]]; then
		number_of_ip6=$(ip -6 addr | grep -c 'inet6 [23]')
		echo
		echo "Which IPv6 address should be used?"
		ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | nl -s ') '
		read -p "IPv6 address [1]: " ip6_number
		until [[ -z "$ip6_number" || "$ip6_number" =~ ^[0-9]+$ && "$ip6_number" -le "$number_of_ip6" ]]; do
			echo "$ip6_number: invalid selection."
			read -p "IPv6 address [1]: " ip6_number
		done
		[[ -z "$ip6_number" ]] && ip6_number="1"
		ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | sed -n "$ip6_number"p)
	fi
	echo
	echo "Do you want to use HTTP proxy?"
	echo "   1) Yes (recommended if clients are behind DPI or live in countries with censorships)"
	echo "   2) No"
	read -p "Use HTTP proxy? [1]: " useHTTPProxy
	#TODO: check default value
	until [[ -z "$useHTTPProxy" || "$useHTTPProxy" =~ ^[12]$ ]]; do
		echo "$useHTTPProxy: invalid selection."
		read -p "Use HTTP proxy? [1]: " useHTTPProxy
	done
	case "$useHTTPProxy" in
		1|"")
		useHTTPProxy=true
		;;
		2)
		useHTTPProxy=false
		;;
	esac
	if [[ "$useHTTPProxy" = "true" ]]; then
		echo
		echo "Do you want to setup the HTTP proxy on this server?"
		echo "   1) Yes (recommended if you don't have an http proxy)"
		echo "   2) No  (only if you have an http proxy ready on another server)"
		read -p "setup HTTP proxy [1]: " setupHTTPProxy
		#TODO: check default value
		until [[ -z "$setupHTTPProxy" || "$setupHTTPProxy" =~ ^[12]$ ]]; do
			echo "$setupHTTPProxy: invalid selection."
			read -p "setup HTTP proxy [1]: " setupHTTPProxy
		done
		case "$setupHTTPProxy" in
			1|"")
			setupHTTPProxy=true
			;;
			2)
			setupHTTPProxy=false
			;;
		esac
		case "$setupHTTPProxy" in
			true|"")
			# If the server is behind NAT, use the correct IP address
			if [[ -n "$public_ip" ]]; then
				proxy_ip="$public_ip"
			else
				echo
				echo "Obtaining public IPv4"
				# Get public IP and sanitize with grep
				get_public_ip=$(grep -m 1 -oE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' <<< "$(wget -T 10 -t 1 -4qO- "http://ip1.dynupdate.no-ip.com/" || curl -m 10 -4Ls "http://ip1.dynupdate.no-ip.com/")")
				read -p "Public IPv4 address [$get_public_ip]: " public_ip
				# If the checkip service is unavailable and user didn't provide input, ask again
				until [[ -n "$get_public_ip" || -n "$public_ip" ]]; do
					echo "Invalid input."
					read -p "Public IPv4 address: " public_ip
				done
				[[ -z "$public_ip" ]] && public_ip="$get_public_ip"
				proxy_ip="$public_ip"
			fi
			;;
			false)
			echo
			echo "Enter the IPv4 of the HTTP proxy"
			read -p "IPv4 of HTTP proxy: " proxy_ip
			until ipvalid "$proxy_ip"; do
			  echo "$proxy_ip: invalid IPv4."
				read -p "IPv4 of HTTP proxy: " proxy_ip
			done
			;;
		esac
		echo
		[[ "$setupHTTPProxy" = "true" ]] && doesOrShould="should" || doesOrShould="does"
		echo "What port $doesOrShould HTTP listen to?"
		read -p "HTTP Port [3128]: " proxy_port
		until [[ -z "$proxy_port" || "$proxy_port" =~ ^[0-9]+$ && "$proxy_port" -le 65535 ]]; do
			echo "$proxy_port: invalid port."
			read -p "HTTP Port [3128]: " proxy_port
		done
		[[ -z "$proxy_port" ]] && proxy_port="3128"
		echo
		echo "OpenVPN will use TCP protocol since we're using HTTP proxy"
		protocol=tcp
	else
		echo
		echo "Which protocol should OpenVPN use?"
		echo "   1) UDP (recommended)"
		echo "   2) TCP"
		read -p "Protocol [1]: " protocol
		until [[ -z "$protocol" || "$protocol" =~ ^[12]$ ]]; do
			echo "$protocol: invalid selection."
			read -p "Protocol [1]: " protocol
		done
		case "$protocol" in
			1|"")
			protocol=udp
			;;
			2)
			protocol=tcp
			;;
		esac
	fi

	echo
	echo "What port should OpenVPN listen to?"
	read -p "Port [1194]: " port
	until [[ -z "$port" || "$port" =~ ^[0-9]+$ && "$port" -le 65535 ]]; do
		echo "$port: invalid port."
		read -p "Port [1194]: " port
	done
	[[ -z "$port" ]] && port="1194"
	echo
	echo "Select a DNS server for the clients:"
	echo "   1) Current system resolvers"
	echo "   2) Google"
	echo "   3) 1.1.1.1"
	echo "   4) OpenDNS"
	echo "   5) Quad9"
	echo "   6) AdGuard"
	read -p "DNS server [1]: " dns
	until [[ -z "$dns" || "$dns" =~ ^[1-6]$ ]]; do
		echo "$dns: invalid selection."
		read -p "DNS server [1]: " dns
	done
	echo
	echo "Enter a name for the first client:"
	read -p "Name [client]: " unsanitized_client
	# Allow a limited set of characters to avoid conflicts
	client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
	[[ -z "$client" ]] && client="client"
	# --- ADDED: Prompt for the initial administrative user ---
	echo
	echo "You need to create the first user account."
	read -p "Enter username for the first user: " vpn_user
	until [[ -n "$vpn_user" ]]; do
		echo "Username cannot be empty."
		read -p "Enter username for the first user: " vpn_user
	done
	read -s -p "Enter password for this user: " vpn_password
	until [[ -n "$vpn_password" ]]; do
		echo
		echo "Password cannot be empty."
		read -s -p "Enter password for this user: " vpn_password
	done
	echo
	# --- END ADDED BLOCK ---
	echo
	echo "OpenVPN installation is ready to begin."
	# Install a firewall in the rare case where one is not already available
	if ! systemctl is-active --quiet firewalld.service && ! hash iptables 2>/dev/null; then
		if [[ "$os" == "centos" || "$os" == "fedora" ]]; then
			firewall="firewalld"
			# We don't want to silently enable firewalld, so we give a subtle warning
			# If the user continues, firewalld will be installed and enabled during setup
			echo "firewalld, which is required to manage routing tables, will also be installed."
		elif [[ "$os" == "debian" || "$os" == "ubuntu" ]]; then
			# iptables is way less invasive than firewalld so no warning is given
			firewall="iptables"
		fi
	fi
	read -n1 -r -p "Press any key to continue..."
	# If running inside a container, disable LimitNPROC to prevent conflicts
	if systemd-detect-virt -cq; then
		mkdir /etc/systemd/system/openvpn-server@server.service.d/ 2>/dev/null
		echo "[Service]
LimitNPROC=infinity" > /etc/systemd/system/openvpn-server@server.service.d/disable-limitnproc.conf
	fi
	if [[ "$os" = "debian" || "$os" = "ubuntu" ]]; then
		apt-get update
		apt-get install -y openvpn openssl ca-certificates $firewall at

	elif [[ "$os" = "centos" ]]; then
		yum install -y epel-release
		yum install -y openvpn openssl ca-certificates $firewall at
	else
		# Else, OS must be Fedora
		dnf install -y openvpn openssl ca-certificates $firewall at
	fi
	# If firewalld was just installed, enable it
	if [[ "$firewall" == "firewalld" ]]; then
		systemctl enable --now firewalld.service
	fi

	# Create a group for our VPN users to make management easier
	groupadd vpnusers &>/dev/null

	# Create the first VPN user in the system
	useradd -M -s /usr/sbin/nologin -g vpnusers "$vpn_user"
	echo "$vpn_user:$vpn_password" | chpasswd

	# Get easy-rsa
	easy_rsa_url='https://github.com/OpenVPN/easy-rsa/releases/download/v3.0.8/EasyRSA-3.0.8.tgz'
	mkdir -p /etc/openvpn/server/easy-rsa/
	{ wget -qO- "$easy_rsa_url" 2>/dev/null || curl -sL "$easy_rsa_url" ; } | tar xz -C /etc/openvpn/server/easy-rsa/ --strip-components 1
	chown -R root:root /etc/openvpn/server/easy-rsa/
	cd /etc/openvpn/server/easy-rsa/
	# Create the PKI, set up the CA and the server and client certificates
	./easyrsa init-pki
	echo 'set_var EASYRSA_BATCH "true"' > /etc/openvpn/server/easy-rsa/vars
	echo 'set_var EASYRSA_PASSOUT ""' >> /etc/openvpn/server/easy-rsa/vars
	./easyrsa build-ca
	EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-server-full server nopass
	# Move the stuff we need
	cp pki/ca.crt pki/private/ca.key pki/issued/server.crt pki/private/server.key /etc/openvpn/server
	# Create the DH parameters file using the predefined ffdhe2048 group
	echo '-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz
+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a
87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7
YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi
7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD
ssbzSibBsu/6iGtCOGEoXJf//////////wIBAg==
-----END DH PARAMETERS-----' > /etc/openvpn/server/dh.pem
	# Generate server.conf
	echo "local $ip
port $port
proto $protocol
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
auth none
topology subnet
server 10.8.0.0 255.255.255.0

# --- USERNAME/PASSWORD AUTHENTICATION ---
plugin /usr/lib/openvpn/openvpn-plugin-auth-pam.so /etc/pam.d/login
verify-client-cert none
username-as-common-name
duplicate-cn
# --- END USERNAME/PASSWORD AUTHENTICATION ---

ifconfig-pool-persist ipp.txt" > /etc/openvpn/server/server.conf

	# IPv6
	if [[ -z "$ip6" ]]; then
		echo 'push "redirect-gateway def1 bypass-dhcp"' >> /etc/openvpn/server/server.conf
	else
		echo 'server-ipv6 fddd:1194:1194:1194::/64' >> /etc/openvpn/server/server.conf
		echo 'push "redirect-gateway def1 ipv6 bypass-dhcp"' >> /etc/openvpn/server/server.conf
	fi
	# DNS
	case "$dns" in
		1|"")
			if grep -q '^nameserver 127.0.0.53' "/etc/resolv.conf"; then
				resolv_conf="/run/systemd/resolve/resolv.conf"
			else
				resolv_conf="/etc/resolv.conf"
			fi
			grep -v '^#\|^;' "$resolv_conf" | grep '^nameserver' | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | while read line; do
				echo "push \"dhcp-option DNS $line\"" >> /etc/openvpn/server/server.conf
			done
		;;
		2)
			echo 'push "dhcp-option DNS 8.8.8.8"' >> /etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 8.8.4.4"' >> /etc/openvpn/server/server.conf
		;;
		3)
			echo 'push "dhcp-option DNS 1.1.1.1"' >> /etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 1.0.0.1"' >> /etc/openvpn/server/server.conf
		;;
		4)
			echo 'push "dhcp-option DNS 208.67.222.222"' >> /etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 208.67.220.220"' >> /etc/openvpn/server/server.conf
		;;
		5)
			echo 'push "dhcp-option DNS 9.9.9.9"' >> /etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 149.112.112.112"' >> /etc/openvpn/server/server.conf
		;;
		6)
			echo 'push "dhcp-option DNS 94.140.14.14"' >> /etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 94.140.15.15"' >> /etc/openvpn/server/server.conf
		;;
	esac
	echo 'push "block-outside-dns"' >> /etc/openvpn/server/server.conf
	echo "keepalive 10 120
cipher none
user nobody
group $group_name
persist-key
persist-tun
status openvpn-status.log
verb 3" >> /etc/openvpn/server/server.conf

	if [[ "$protocol" = "udp" ]]; then
		echo "explicit-exit-notify" >> /etc/openvpn/server/server.conf
	fi
	# Enable net.ipv4.ip_forward for the system
	echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/30-openvpn-forward.conf
	# Enable without waiting for a reboot or service restart
	echo 1 > /proc/sys/net/ipv4/ip_forward

	# Add TCP keepalive settings for connection stability through NAT/firewalls
	echo 'net.ipv4.tcp_keepalive_time=120
net.ipv4.tcp_keepalive_intvl=30
net.ipv4.tcp_keepalive_probes=8' > /etc/sysctl.d/60-tcp-keepalive.conf
	# Apply all sysctl settings without needing a reboot
	sysctl --system
	
	if [[ -n "$ip6" ]]; then
		# Enable net.ipv6.conf.all.forwarding for the system
		echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.d/30-openvpn-forward.conf
		# Enable without waiting for a reboot or service restart
		echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
	fi
	if systemctl is-active --quiet firewalld.service; then
		# Using both permanent and not permanent rules to avoid a firewalld
		# reload.
		# We don't use --add-service=openvpn because that would only work with
		# the default port and protocol.
		firewall-cmd --add-port="$port"/"$protocol"
		firewall-cmd --zone=trusted --add-source=10.8.0.0/24
		firewall-cmd --permanent --add-port="$port"/"$protocol"
		firewall-cmd --permanent --zone=trusted --add-source=10.8.0.0/24
		# Set NAT for the VPN subnet
		firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip"
		firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip"
		if [[ -n "$ip6" ]]; then
			firewall-cmd --zone=trusted --add-source=fddd:1194:1194:1194::/64
			firewall-cmd --permanent --zone=trusted --add-source=fddd:1194:1194:1194::/64
			firewall-cmd --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
			firewall-cmd --permanent --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
		fi
	else
		# Create a service to set up persistent iptables rules
		iptables_path=$(command -v iptables)
		ip6tables_path=$(command -v ip6tables)
		# nf_tables is not available as standard in OVZ kernels. So use iptables-legacy
		# if we are in OVZ, with a nf_tables backend and iptables-legacy is available.
		if [[ $(systemd-detect-virt) == "openvz" ]] && readlink -f "$(command -v iptables)" | grep -q "nft" && hash iptables-legacy 2>/dev/null; then
			iptables_path=$(command -v iptables-legacy)
			ip6tables_path=$(command -v ip6tables-legacy)
		fi
		echo "[Unit]
Before=network.target
[Service]
Type=oneshot
ExecStart=$iptables_path -t nat -A POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $ip
ExecStart=$iptables_path -I INPUT -p $protocol --dport $port -j ACCEPT
ExecStart=$iptables_path -I FORWARD -s 10.8.0.0/24 -j ACCEPT
ExecStart=$iptables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$iptables_path -t nat -D POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $ip
ExecStop=$iptables_path -D INPUT -p $protocol --dport $port -j ACCEPT
ExecStop=$iptables_path -D FORWARD -s 10.8.0.0/24 -j ACCEPT
ExecStop=$iptables_path -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" > /etc/systemd/system/openvpn-iptables.service
		if [[ -n "$ip6" ]]; then
			echo "ExecStart=$ip6tables_path -t nat -A POSTROUTING -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to $ip6
ExecStart=$ip6tables_path -I FORWARD -s fddd:1194:1194:1194::/64 -j ACCEPT
ExecStart=$ip6tables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$ip6tables_path -t nat -D POSTROUTING -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to $ip6
ExecStop=$ip6tables_path -D FORWARD -s fddd:1194:1194:1194::/64 -j ACCEPT
ExecStop=$ip6tables_path -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" >> /etc/systemd/system/openvpn-iptables.service
		fi
		echo "RemainAfterExit=yes
[Install]
WantedBy=multi-user.target" >> /etc/systemd/system/openvpn-iptables.service
		systemctl enable --now openvpn-iptables.service
	fi
	# If SELinux is enabled and a custom port was selected, we need this
	if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$port" != 1194 ]]; then
		# Install semanage if not already present
		if ! hash semanage 2>/dev/null; then
			if [[ "$os_version" -eq 7 ]]; then
				# Centos 7
				yum install -y policycoreutils-python
			else
				# CentOS 8 or Fedora
				dnf install -y policycoreutils-python-utils
			fi
		fi
		semanage port -a -t openvpn_port_t -p "$protocol" "$port"
	fi
	# If the server is behind NAT, use the correct IP address
	[[ -n "$public_ip" ]] && ip="$public_ip"
	# client-common.txt is created so we have a template to add further users later
	echo "client
dev tun
proto $protocol
auth-user-pass" > /etc/openvpn/server/client-common.txt
	if [[ "$useHTTPProxy" = "true" ]]; then
		echo "http-proxy $proxy_ip $proxy_port" >> /etc/openvpn/server/client-common.txt
	fi
	echo "remote $ip $port
resolv-retry infinite
nobind
persist-key
persist-tun
auth none
cipher none
ignore-unknown-option block-outside-dns
setenv CLIENT_CERT 0
block-outside-dns
verb 3" >> /etc/openvpn/server/client-common.txt
	# Detect the correct OpenVPN service name
	if systemctl list-unit-files | grep -q 'openvpn-server@'; then
		service_name='openvpn-server@server.service'
	elif systemctl list-unit-files | grep -q 'openvpn@'; then
		service_name='openvpn@server.service'
	else
		echo "Could not find a valid OpenVPN service file."
		exit 1
	fi

	# Enable and start the OpenVPN service
	systemctl enable --now "$service_name"
	# Generates the custom client.ovpn
	new_client
	echo
	echo "Finished!"
	if [[ "$setupHTTPProxy" = "true" && "$os" != "none" ]]; then
		apt-get update
		apt-get install squid -y
		cp /etc/squid/squid.conf /etc/squid/squid.conf.orig

		# Write the new, secure configuration for OpenVPN tunneling
		echo "# This Squid configuration is tailored for OpenVPN tunneling.
# It only allows the CONNECT method on the OpenVPN port, preventing abuse.

# Define the method used by OpenVPN to tunnel through the proxy
acl CONNECT method CONNECT

# Define the port our OpenVPN server is listening on.
# Note: $port is the OpenVPN server port (e.g., 1194), NOT the proxy port.
acl OpenVPN_port port $port

# --- ACCESS RULES ---
# Rules are checked in order. The first match wins.

# 1. Allow CONNECT requests that are trying to reach our OpenVPN server port.
#    This is the key rule. It allows the connection regardless of the hostname used.
http_access allow CONNECT OpenVPN_port

# 2. Deny all other requests.
#    This is the firewall that prevents your proxy from being used for anything else.
http_access deny all

# --- CONFIGURATION ---
# Set the port for Squid to listen on
http_port $proxy_port

# Set the coredump directory
coredump_dir /var/spool/squid

# Turn off verbose refresh patterns for this use case
refresh_pattern . 0 20% 4320" > /etc/squid/squid.conf
	systemctl restart squid
	fi
	echo
	echo "The client configuration is available in:" ~/"$client.ovpn"
	echo "New clients can be added by running this script again."
else
	clear
	echo "OpenVPN is already installed."
	echo
	echo "Select an option:"
	echo "   1) Add a new client"
	echo "   2) Delete an existing user"
	echo "   3) Remove OpenVPN"
	echo "   4) Exit"
	read -p "Option: " option
	until [[ "$option" =~ ^[1-4]$ ]]; do
		echo "$option: invalid selection."
		read -p "Option: " option
	done
	case "$option" in
		1)
			echo
			echo "Provide a new username:"
			read -p "Username: " username
			# Check if the username is empty or already exists     
			while [ -z "$username" ] || id -u "$username" &>/dev/null; do
				echo "Invalid username or user already exists."
				read -p "Username: " username
			done

			# Ask for a password for the new user
			read -s -p "Enter a password for $username: " password
			until [[ -n "$password" ]]; do
				echo
				echo "Password cannot be empty."
				read -s -p "Enter a password for $username: " password
			done
			echo

			# --- ADDED: Prompt for account validity ---
			echo
			echo "Set an expiration time for this user (leave blank or 0 for never)."
			read -p "Days: " days
			read -p "Hours: " hours
			read -p "Minutes: " minutes

			# Default to 0 if input is empty
			days=${days:-0}
			hours=${hours:-0}
			minutes=${minutes:-0}
			# --- END ADDED BLOCK ---

			expire_date_cmd=""
			total_minutes=$((days * 1440 + hours * 60 + minutes))

			if [[ "$total_minutes" -gt 0 ]]; then
				# Calculate the future date and format it as YYYY-MM-DD
				expire_date=$(date -d "+$days days $hours hours $minutes minutes" +%Y-%m-%d)
				expire_date_cmd="-e $expire_date"
				echo "User '$username' will expire on: $expire_date"
			else
				echo "User '$username' will not expire."
			fi

			# Create the user in the system with or without the expiration date
			if [[ "$total_minutes" -gt 0 ]]; then
				useradd -M -s /usr/sbin/nologin -g vpnusers "$username"
				echo "$username:$password" | chpasswd
				echo "deluser $username" | at now + $total_minutes minutes
				echo "User '$username' will expire in $total_minutes minutes."
			else
				useradd -M -s /usr/sbin/nologin -g vpnusers "$username"
				echo "$username:$password" | chpasswd
				echo "User '$username' will not expire."
			fi

			# Generate a new .ovpn file for this specific user
			{
			cat /etc/openvpn/server/client-common.txt
			echo "<auth-user-pass>"
			echo "$username"
			echo "$password"
			echo "</auth-user-pass>"
			echo
			echo "<ca>"
			cat /etc/openvpn/server/easy-rsa/pki/ca.crt
			echo "</ca>"

			} > ~/"$username".ovpn

			echo
			echo "User '$username' was added. Their configuration file is available at:" ~/"$username.ovpn"
			exit
		;;
		2)
			# Get the list of users in the vpnusers group
			mapfile -t user_list < <(getent group vpnusers | cut -d: -f4 | sed 's/,/\n/g' | grep -v '^$')
			number_of_users=${#user_list[@]}

			if [[ "$number_of_users" = 0 ]]; then
				echo
				echo "There are no VPN users to delete!"
				exit
			fi
			echo
			echo "Select the user to delete:"
			# Display the list of users
			for i in "${!user_list[@]}"; do
				printf "   %s) %s\n" "$((i+1))" "${user_list[$i]}"
			done
			read -p "User: " user_number
			until [[ "$user_number" =~ ^[0-9]+$ && "$user_number" -ge 1 && "$user_number" -le "$number_of_users" ]]; do
				echo "$user_number: invalid selection."
				read -p "User: " user_number
			done

			user_to_delete="${user_list[$((user_number-1))]}"

			echo
			read -p "Confirm deletion of user '$user_to_delete'? [y/N]: " confirm_delete
			if [[ "$confirm_delete" =~ ^[yY]$ ]]; then
				# Delete the user from the system
				deluser "$user_to_delete"
				echo
				echo "User '$user_to_delete' has been deleted."
			else
				echo
				echo "User deletion aborted."
			fi
			exit
		;;
		3)
			echo
			read -p "Confirm OpenVPN removal? [y/N]: " remove
			until [[ "$remove" =~ ^[yYnN]*$ ]]; do
				echo "$remove: invalid selection."
				read -p "Confirm OpenVPN removal? [y/N]: " remove
			done
			if [[ "$remove" =~ ^[yY]$ ]]; then
				if [[ -e /etc/squid/squid.conf ]]; then
					echo
					echo "Do you want Squid proxy removed too?"
					echo "   1) Yes (recommended if HTTP proxy was enabled)"
					echo "   2) No"
					read -p "Remove Squid? [1]: " removeSquid
					#TODO: check default value
					until [[ -z "$removeSquid" || "$removeSquid" =~ ^[12]$ ]]; do
						echo "$removeSquid: invalid selection."
						read -p "Remove Squid? [1]: " removeSquid
					done
					case "$removeSquid" in
						1|"")

						if [[ "$os" = "debian" || "$os" = "ubuntu" ]]; then
							echo "removing Squid"
							systemctl disable --now squid.service
							rm -f /etc/squid/whitelistIPs.txt
							rm -f /etc/squid/blacklistIPs.txt
							rm -f /etc/squid/squid.conf.orig
							apt-get remove --purge -y squid
							echo "Squid removed successfuly."
						fi

						;;
						2)
						;;
					esac
				fi
				port=$(grep '^port ' /etc/openvpn/server/server.conf | cut -d " " -f 2)
				protocol=$(grep '^proto ' /etc/openvpn/server/server.conf | cut -d " " -f 2)
				if systemctl is-active --quiet firewalld.service; then
					ip=$(firewall-cmd --direct --get-rules ipv4 nat POSTROUTING | grep '\-s 10.8.0.0/24 '"'"'!'"'"' -d 10.8.0.0/24' | grep -oE '[^ ]+$')
					# Using both permanent and not permanent rules to avoid a firewalld reload.
					firewall-cmd --remove-port="$port"/"$protocol"
					firewall-cmd --zone=trusted --remove-source=10.8.0.0/24
					firewall-cmd --permanent --remove-port="$port"/"$protocol"
					firewall-cmd --permanent --zone=trusted --remove-source=10.8.0.0/24
					firewall-cmd --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip"
					firewall-cmd --permanent --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip"
					if grep -qs "server-ipv6" /etc/openvpn/server/server.conf; then
						ip6=$(firewall-cmd --direct --get-rules ipv6 nat POSTROUTING | grep '\-s fddd:1194:1194:1194::/64 '"'"'!'"'"' -d fddd:1194:1194:1194::/64' | grep -oE '[^ ]+$')
						firewall-cmd --zone=trusted --remove-source=fddd:1194:1194:1194::/64
						firewall-cmd --permanent --zone=trusted --remove-source=fddd:1194:1194:1194::/64
						firewall-cmd --direct --remove-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
						firewall-cmd --permanent --direct --remove-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
					fi
				else
					systemctl disable --now openvpn-iptables.service
					rm -f /etc/systemd/system/openvpn-iptables.service
				fi
				if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$port" != 1194 ]]; then
					semanage port -d -t openvpn_port_t -p "$protocol" "$port"
				fi
				# Detect the correct OpenVPN service name to disable
				if systemctl list-unit-files | grep -q 'openvpn-server@'; then
					service_name='openvpn-server@server.service'
				elif systemctl list-unit-files | grep -q 'openvpn@'; then
					service_name='openvpn@server.service'
				fi

				if [[ -n "$service_name" ]]; then
					systemctl disable --now "$service_name"
				fi

				rm -rf /etc/openvpn/server
				rm -f /etc/systemd/system/openvpn-server@server.service.d/disable-limitnproc.conf
				rm -f /etc/sysctl.d/30-openvpn-forward.conf
				if [[ "$os" = "debian" || "$os" = "ubuntu" ]]; then
					apt-get remove --purge -y openvpn
				else
					# Else, OS must be CentOS or Fedora
					yum remove -y openvpn
				fi


				echo
				echo "OpenVPN over Proxy removed!"
			else
				echo
				echo "OpenVPN over Proxy removal aborted!"
			fi
			exit
		;;
		4)
			exit
		;;
	esac
fi

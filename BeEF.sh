#!/data/data/com.termux/files/usr/bin/bash
#
# Created by: Termux Hacking
#
# BeEF
#
# VARIABLES
#
PWD=$(pwd)
source ${PWD}/Colors.sh
#
# FUNCIONES
#
function Error {
echo -e "${rojo}
┌═════════════════════┐
█ ${blanco}¡OPCIÓN INCORRECTA! ${rojo}█
└═════════════════════┘"
	sleep 1.5
	clear
}
function BeEF {
	sleep 0.5
	clear
echo -e "${verde}
				     .O,
                                     lkOl                                                                  od cOc                                                                'X,  cOo.
                                      cX,   ,dkc.
                                       ;Kd.    ,odo,.
                                        .dXl   .  .:xkl'
                                          'OKc  .;c'  ,oOk:
                                            ,kKo. .cOkc. .lOk:.
                                              .dXx.  :KWKo. 'dXd.
                                                .oXx.  cXWW0c..dXd.
                                                  oW0   .OWWWNd.'KK.
                                          ....,;lkNWx     KWWWWX:'XK.
  ,o:,                          .,:odkO00XNK0Okxdlc,.     .KWWWWWWddW.
  K::Ol                   .:d0NXK0OkxdoxO'             .lXWWWWWWWWKW0.
  od  d0.              .l0NKOxdooooooox0.        .,cdOXWWWWWWWWWWWWWx
  :O   ;K;           ;kN0kooooooooooooK:  .':ok0NWWWWWWWWWWWWWWWWWWK.
  'X    .Kl        ;KNOdooooooooooooooXkkXWWWWWWWWWWWWWWWWWWWWWWWNd.
  .N. o. .Kl     'OW0doooooooooooooodkXWWWWWWWWWWWWWWWWWWWWWWWW0l.
   0l oK' .kO:';kNNkoooooooooooook0XWWWWWWWWWWWWWWWWWWWWWWWKx:.
   lX.,WN:  .:c:xWkoooooooooood0NWW0OWWWWWWWWWWWWWWWWWWWKo.
    0O.0WWk'   .XKoooooooooooONWWNo  dWWWWWWWWWWWWWWWWWl
     oKkNWWWX00NWXdooooooooxXWWNk'   dWWWWWWWWWWWWWWWWX
      .cONWWWWWWWWOoooooooONWWK:...c0WWWWWWWWWWWWWWWWWW:
         .;oONWWWWxooooodKWWWWWWWWWWWWWWWWWWWWWWWWWWWWWX.
	      'XW0oooookNWWWWW ▄▄▄▄▄▄              ▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄
              oW0ooooo0WWWWWWW ██▀▀▀▀██            ██▀▀▀▀▀▀  ██▀▀▀▀▀▀
             ;NXdooodKWWWWWWWW ██    ██   ▄████▄   ██        ██
          ;xkOOdooooxOO0KNWWWW ███████   ██▄▄▄▄██  ███████   ███████
         .NOoddxkkkkxxdoookKWW ██    ██  ██▀▀▀▀▀▀  ██        ██
          :KNWWWWWWWWWWX0xooON ██▄▄▄▄██  ▀██▄▄▄▄█  ██▄▄▄▄▄▄  ██
         .xNXxKWWWWWWWOXWWXxoK ▀▀▀▀▀▀▀     ▀▀▀▀▀   ▀▀▀▀▀▀▀▀  ▀▀
         OWl cNWWWWWWWk oNWNxKWWWWWWWWWWWWWWWWWNOl.
        ,Wk  xWWWWWWWWd  xWWNWWWWWWWWWWWWXOdc,.
        .N0   lOXNX0x;  .KWWWWWWWWWWWNkc.
         :NO,         'lXWWWWWWWWWNk:.
          .dXN0OkxkO0NWWWWWWWWWWKl.
             .';o0WWWWWWWWWWWNk;
                  .cxOKXKKOd;.
"${blanco}
}
#
# CÓDIGO
#
cd
BeEF
if [ -x $PREFIX/bin/msfconsole ]
then
BeEF
else
while :
do
echo -e -n "${verde}
┌═══════════════════════════════════┐
█ ${blanco}SE INSTALARÁ METASPLOIT-FRAMEWORK ${verde}█
█   ${blanco}SELECCIONE SU VERSIÓN ANDROID   ${verde}█
└═══════════════════════════════════┘

┌═══════════════════════════┐
█ [${blanco}1${verde}] ┃ ${blanco}5.0.1 - 6.0.1       ${verde}█
█═══════════════════════════█
█ [${blanco}2${verde}] ┃ ${blanco}7.0.1 - SUPERIOR    ${verde}█
█═══════════════════════════█
█ [${blanco}3${verde}] ┃ ${blanco}OMITIR INSTALACIÓN  ${verde}█
└═══════════════════════════┘
┃
└═>>> "${blanco}

read -r Metasploit

[ "$Metasploit" == "1" ]||[ "$Metasploit" == "2" ]||[ "$Metasploit" == "3" ] && break
Error
done

case $Metasploit in
	1)
		sleep 0.5
echo -e "${verde}
┌════════════════════════════════════┐
█ ${blanco}INSTALANDO METASPLOIT-FRAMEWORK... ${verde}█
└════════════════════════════════════┘
"${blanco}
		pkg install -y curl > /dev/null 2>&1
		pkg install ruby -y > /dev/null 2>&1
		gem install bundler:1.17.3
		curl -LO https://github.com/termux/termux-packages/files/3995119/metasploit_5.0.65-1_all.deb.gz
		gunzip metasploit_5.0.65-1_all.deb.gz
		dpkg -i metasploit_5.0.65-1_all.deb
		apt install -f -y
echo -e "${verde}
┌════════════════════════════════┐
█ ${blanco}METASPLOIT-FRAMEWORK INSTALADO ${verde}█
└════════════════════════════════┘
"${blanco}
		sleep 2
		clear
		;;
	2)
		sleep 0.5
echo -e "${verde}
┌════════════════════════════════════┐
█ ${blanco}INSTALANDO METASPLOIT-FRAMEWORK... ${verde}█
└════════════════════════════════════┘
"${blanco}
		pkg install -y ruby > /dev/null 2>&1
		pkg install -y unstable-repo > /dev/null 2>&1
		pkg install -y metasploit
echo -e "${verde}
┌════════════════════════════════┐
█ ${blanco}METASPLOIT-FRAMEWORK INSTALADO ${verde}█
└════════════════════════════════┘
"${blanco}
		sleep 2
		clear
		;;
	3)
		sleep 0.5
		clear
esac
fi
BeEF
echo -e "${verde}
┌═══════════════════════════════┐
█       ${blanco}SE INSTALARÁ BeEF       ${verde}█
█                               █
█ ${blanco}PRESIONE ENTER PARA CONTINUAR ${verde}█
└═══════════════════════════════┘"
read
cd
echo -e "${verde}
┌══════════════════════┐
█ ${blanco}Instalando nodejs... ${verde}█
└══════════════════════┘"
pkg install -y nodejs > /dev/null 2>&1
echo -e "${verde}
┌═══════════════════┐
█ ${blanco}Instalando vim... ${verde}█
└═══════════════════┘"
pkg install -y vim > /dev/null 2>&1
echo -e "${verde}
┌═══════════════════┐
█ ${blanco}Instalando git... ${verde}█
└═══════════════════┘"
pkg install -y git > /dev/null 2>&1
echo -e "${verde}
┌════════════════════┐
█ ${blanco}Instalando BeEF... ${verde}█
└════════════════════┘"
git clone https://github.com/beefproject/beef > /dev/null 2>&1
cd beef > /dev/null 2>&1
./update-beef > /dev/null 2>&1
BeEF
echo -e -n "${verde}
┌═══════════════════════════════┐
█ ${blanco}INTRODUCIR UN USUARIO PARA EL ${verde}█
█   ${blanco}PANEL DE CONTROL DE BeEF    ${verde}█
└═══════════════════════════════┘
┃
└═>>> "${blanco}

read -r usuario

echo -e -n "${verde}
┌════════════════════════════════┐
█ ${blanco}INTRODUCIR UNA CONTRASEÑA PARA ${verde}█
█  ${blanco}EL PANEL DE CONTROL DE BeEF   ${verde}█
└════════════════════════════════┘
┃
└═>>> "${blanco}

read -r clave

rm config.yaml

echo -e "#
# Copyright (c) 2006-2020 Wade Alcorn - wade@bindshell.net
# Browser Exploitation Framework (BeEF) - http://beefproject.com
# See the file 'doc/COPYING' for copying permission
#
# BeEF Configuration file

beef:
    version: '0.5.0.0-alpha-pre'
    # More verbose messages (server-side)
    debug: false
    # More verbose messages (client-side)
    client_debug: false
    # Used for generating secure tokens
    crypto_default_value_length: 80

    # Credentials to authenticate in BeEF.
    # Used by both the RESTful API and the Admin interface
    credentials:
        user:   '$usuario'
        passwd: '$clave'

    # Interface / IP restrictions
    restrictions:
        # subnet of IP addresses that can hook to the framework
        permitted_hooking_subnet: ['0.0.0.0/0', '::/0']
        # subnet of IP addresses that can connect to the admin UI
        #permitted_ui_subnet: ['127.0.0.1/32', '::1/128']
        permitted_ui_subnet: ['0.0.0.0/0', '::/0']
        # slow API calls to 1 every  api_attempt_delay  seconds
        api_attempt_delay: '0.05'

    # HTTP server
    http:
        debug: false #Thin::Logging.debug, very verbose. Prints also full exception stack trace.
        host: '0.0.0.0'
        port: '3000'

        # Decrease this setting to 1,000 (ms) if you want more responsiveness
        #  when sending modules and retrieving results.
        # NOTE: A poll timeout of less than 5,000 (ms) might impact performance
        #  when hooking lots of browsers (50+).
        # Enabling WebSockets is generally better (beef.websocket.enable)
        xhr_poll_timeout: 1000

        # Host Name / Domain Name
        # If you want BeEF to be accessible via hostname or domain name (ie, DynDNS),
        #   set the public hostname below:
        #public: ''      # public hostname/IP address

        # Reverse Proxy / NAT
        # If you want BeEF to be accessible behind a reverse proxy or NAT,
        #   set both the publicly accessible hostname/IP address and port below:
        # NOTE: Allowing the reverse proxy will enable a vulnerability where the ui/panel can be spoofed
        #   by altering the X-FORWARDED-FOR ip address in the request header.
        allow_reverse_proxy: false
        #public: ''      # public hostname/IP address
        #public_port: '' # public port (experimental)

        # Hook
        hook_file: '/hook.js'
        hook_session_name: 'BEEFHOOK'

        # Allow one or multiple origins to access the RESTful API using CORS
        # For multiple origins use: 'http://browserhacker.com, http://domain2.com'
        restful_api:
            allow_cors: false
            cors_allowed_domains: 'http://browserhacker.com'

        # Prefer WebSockets over XHR-polling when possible.
        websocket:
            enable: false
            port: 61985 # WS: good success rate through proxies
            # Use encrypted 'WebSocketSecure'
            # NOTE: works only on HTTPS domains and with HTTPS support enabled in BeEF
            secure: true
            secure_port: 61986 # WSSecure
            ws_poll_timeout: 5000 # poll BeEF every x second, this affects how often the browser can have a command execute on it
            ws_connect_timeout: 500 # useful to help fingerprinting finish before establishing the WS channel

        # Imitate a specified web server (default root page, 404 default error page, 'Server' HTTP response header)
        web_server_imitation:
            enable: true
            type: 'apache' # Supported: apache, iis, nginx
            hook_404: false # inject BeEF hook in HTTP 404 responses
            hook_root: false # inject BeEF hook in the server home page
        # Experimental HTTPS support for the hook / admin / all other Thin managed web services
        https:
            enable: false
            # In production environments, be sure to use a valid certificate signed for the value
            # used in beef.http.public (the domain name of the server where you run BeEF)
            key: 'beef_key.pem'
            cert: 'beef_cert.pem'

    database:
        file: 'beef.db'

    # Autorun Rule Engine
    autorun:
        # this is used when rule chain_mode type is nested-forward, needed as command results are checked via setInterval
        # to ensure that we can wait for async command results. The timeout is needed to prevent infinite loops or eventually
        # continue execution regardless of results.
        # If you're chaining multiple async modules, and you expect them to complete in more than 5 seconds, increase the timeout.
        result_poll_interval: 300
        result_poll_timeout: 5000

        # If the modules doesn't return status/results and timeout exceeded, continue anyway with the chain.
        # This is useful to call modules (nested-forward chain mode) that are not returning their status/results.
        continue_after_timeout: true

    # Enables DNS lookups on zombie IP addresses
    dns_hostname_lookup: false

    # IP Geolocation
    # NOTE: requires MaxMind database. Run ./updated-geoipdb to install.
    geoip:
        enable: true
        database: '/opt/GeoIP/GeoLite2-City.mmdb'

    # Integration with PhishingFrenzy
    # If enabled BeEF will try to get the UID parameter value from the hooked URI, as this is used by PhishingFrenzy
    # to uniquely identify the victims. In this way you can easily associate phishing emails with hooked browser.
    integration:
        phishing_frenzy:
            enable: false

    # You may override default extension configuration parameters here
    # Note: additional experimental extensions are available in the 'extensions' directory
    #       and can be enabled via their respective 'config.yaml' file
    extension:
        admin_ui:
            enable: true
            base_path: '/ui'
        demos:
            enable: true
        events:
            enable: true
        evasion:
            enable: false
        requester:
            enable: true
        proxy:
            enable: true
        network:
            enable: true
        metasploit:
            enable: false
        social_engineering:
            enable: true
        xssrays:
            enable: true" >> config.yaml

while :
do
BeEF
echo -e -n "${verde}
┌══════════════════════════════┐
█ ${blanco}BeEF INSTALADO CORRECTAMENTE ${verde}█
█                              █
█      ${blanco}¿DESEA EJECUTARLO?      ${verde}█
└══════════════════════════════┘
┃
┌══════════════┐
█ [${blanco}1${verde}] ┃   ${blanco}SI   ${verde}█
█══════════════█
█ [${blanco}2${verde}] ┃   ${blanco}NO   ${verde}█
└══════════════┘
┃
└>>> "${blanco}

read -r opcion

[ "$opcion" == "1" ]||[ "$opcion" == "2" ] && break
Error
done

case $opcion in
	1)
		BeEF
		./beef
		;;
	2)
		sleep 0.5
		cd
		cd BeEF
esac

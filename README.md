# Sipd

## Description

Sipd - SIP server with registrar functions and PBX features (forwarding, interception and transfer of calls, the calls by short number, voice guidance).

## Setting

Sipd is controlled by only one configuration file sip.conf, which should be in the working directory of the server, and by the flags of the program start.

Flag | Description
-|-
-a | print about
-b | listen address (default "127.0.0.1:5060")
-c | current country code (default "7")
-cc | current city code (default "495")
-d | The debug mode outputs to the current terminal all SIP messages of the server
-s directory | the server's working directory (default .)
-r | reloads data from sip.conf
-v | outputs name, version of the program, current hostname (realm)

The sip.conf file is structured text, broken up using headers in square brackets into sections, which in turn describe the parameters of one of the SIP clients served on the server. The header itself is the name of the client. Followed lines in the format key=value are it's parameters. All lines beginning with a semicolon (;) character are comments and are ignored when the configuration is loaded.

Example of sip.conf file contents:

    ; sip.conf
    ;

    [foo]
    accountcode=FOOBAR
    context=domestic
    secret=abc
    permit=192.168/16,10/8
    ; short phone number
    exten=1001

    [bar]
    accountcode=FOOBAR
    host=192.168.1.129:5060
    context=international
    secret=cba
    permit=192.168.1.129/32
    exten=1002

    [siphone1]
    accountcode=HOME
    dialplan=.+
    secret=12345
    exten=1001(2)

    [siphone2]
    accountcode=HOME
    dialplan=.+
    secret=4321
    ; long, short and call forward phone numbers
    exten=4999876543#1002=4991234567

    [GATE1]
    accountcode=gateways
    host=192.168.1.200:5060
    exten=9995999 ; gateway prefix when accountcode is gateways

    [GATE2]
    accountcode=gateways
    host=192.168.1.201:5060
    exten=9

    [MEDIAGATE]
    accountcode=mediagates
    host=192.168.1.100:5070

    ; EOF


A section can contains the following keys.

Key | Description | Default value
-|-|-
accountcode | the client group ID combines them for calls by short numbers and pickups in the limits of this group |
secret | password for this SIP client (its name is indicated in the square brackets of the section header) |
permit | comma separated IP (CIDR) addresses from which the client's requests can arrive |
host | static client IP address (no registration) |
exten | telephone number of the client in the format L#S(N)=F for connecting with him by phone number L or short number S, or transferring the connection, if not available, to another client under the serial number N in the side of the group (accountcode), or forwarding to the phone number F (if redirection is needed "on unavailable", then the symbol ~ is used instead of the symbol =) |
callerid | identifier of the calling channel for substitution, if necessary
dialplan | a standard regular expression (PCRE) that limits the range of called telephone numbers for a given SIP client (the call will take place if the dialed phone number matches this regular expression, otherwise it does not) | .+
context | It is used when there is no dialplan key and is replaced by it with a value according to the value of this context key (for example, context=em is perceived as dialplan=^7495\d{2,3}$)

## Exploitation

Starting the server from its working directory is performed by the command:

    $ sipd &

After the changes made in the sip.conf file, you must tell the running SIP server to overload the configuration. This will not affect the current state of the connections served by the server.

    $ sipd -r

The server stops using the CLI command:

    $ pkill sipd

## PBX features

A registered customer can use the following built-in PBX services by dialing the following command combinations on his phone:

Command | Service
-|-
*11 | Interception of a call (ring) from a nearby phone with the same accountcode
*72XXXXXXXXXX | Setting call forwarding to a number XXXXXXXXXX
*71XXXXXXXXXX | Setting call forwarding to a number XXXXXXXXXX if the base number will be not available (off, busy etc)
*72 | Check current forwarding. The response will be dictated by the number of forwarding, if the media gateway is configured (silence if not)
*73 | Remove current call forwarding

## License

Sipd server is distributed under license [MIT](https://github.com/gbazil/sipd/blob/master/LICENSE)

## Author

Vasily Suvorov (gbazil)

---
[bazil.pro](https://gbazil.github.io) Moscow 2018

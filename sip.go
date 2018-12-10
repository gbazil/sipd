// Copyright (c) 2018 Vasily Suvorov, http://bazil.pro <gbazil@gmail.com>
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.
//

package main

import (
	"bufio"
	"crypto/md5"
	"crypto/rand"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

const (
	NL = "\r\n"
	SP = ": "
)

type SIP map[string]string

func (m SIP) Parse(s string) {
	var f bool
	for i, v := range strings.Split(s, NL) {
		if i == 0 {
			m["Request"] = v
		} else if !f && len(v) > 0 {
			pair := strings.Split(v, SP)
			if len(m[pair[0]]) > 0 {
				m[pair[0]] = m[pair[0]] + "," + pair[1]
			} else {
				m[pair[0]] = pair[1]
			}
		} else {
			f = true
		}

		if f && len(v) > 0 {
			m["Content"] += v + NL
		}
	}
}

func (m SIP) String() string {
	var s string
	for k, v := range m {
		if k != "Request" && k != "Content" {
			if k == "Via" {
				for _, vv := range strings.Split(v, ",") {
					s += k + SP + vv + NL
				}
			} else {
				s += k + SP + v + NL
			}
		}
	}

	return m["Request"] + NL + s + NL + m["Content"]
}

func (m SIP) Clone() SIP {
	clone := make(SIP)
	for key, val := range m {
		clone[key] = val
	}

	return clone
}

func (m SIP) MethodFrom(key string) string {
	return regexp.MustCompile(`\S*`).FindString(m[key])
}

func (m SIP) NameFrom(key string) string {
	return strings.TrimPrefix(regexp.MustCompile(`sip:[^@]*`).FindString(m[key]), "sip:")
}

func (m SIP) NameFor(key, name string) {
	if oldname := m.NameFrom(key); oldname != "" {
		m[key] = strings.Replace(m[key], "sip:"+oldname, "sip:"+name, 1)
	}
}

func (m SIP) AddrFrom(key string) (addr string) {
	if addr = regexp.MustCompile(`\d+\.\d+\.\d+\.\d+:\d+`).FindString(m[key]); addr == "" {
		if addr = regexp.MustCompile(`\d+\.\d+\.\d+\.\d+`).FindString(m[key]); addr == "" {
			addr = strings.TrimPrefix(regexp.MustCompile(`@[\w.-]*`).FindString(m[key]), "@")
		}
	}

	return
}

func (m SIP) AddrFor(key, addr string) {
	if s := m.AddrFrom(key); s != "" {
		m[key] = strings.Replace(m[key], s, addr, 1)
	}
}

func (m SIP) ValueFrom(key, value string) string {
	s := strings.Replace(m[key], `"`, ``, -1)
	return strings.TrimPrefix(regexp.MustCompile(value+`=[^ ,;>]*`).FindString(s), value+`=`)
}

func (m SIP) Reply(addr *net.UDPAddr) {
	delete(m, "Allow")
	delete(m, "Supported")

	delete(m, "Content")
	delete(m, "Content-Type")
	m["Content-Length"] = "0"

	pack := []byte(m.String())
	conn.WriteToUDP(pack, addr)
	if *debug {
		fmt.Printf(">> %s\n%s\n", addr, pack)
	}
}

func (m SIP) Send(addr string) {
	if udpaddr, err := net.ResolveUDPAddr("udp", addr); err == nil {
		if strings.HasSuffix(m["Call-ID"], callidsuffix) {
			m["Call-ID"] = strings.TrimSuffix(m["Call-ID"], callidsuffix)
		} else {
			m["Call-ID"] += callidsuffix
		}

		pack := []byte(m.String())
		conn.WriteToUDP(pack, udpaddr)
		if *debug {
			fmt.Printf(">> %s\n%s\n", udpaddr, pack)
		}
	}
}

func (m SIP) AgiSend() (ret string) {
	var conn net.Conn
	var uniqueid, addr string
	err := db.QueryRow("SELECT callerid, addr FROM register WHERE acode = 'agigates' ORDER BY name LIMIT 1 OFFSET 0").Scan(&uniqueid, &addr)
	if err == nil {
		conn, err = net.DialTimeout("tcp", addr, time.Second*2)
		if err != nil {
			db.QueryRow("SELECT callerid, addr FROM register WHERE acode = 'agigates' ORDER BY name LIMIT 1 OFFSET 1").Scan(&uniqueid, &addr)
			conn, err = net.DialTimeout("tcp", addr, time.Second*2)
			if err != nil {
				return
			}
		}
	}

	defer conn.Close()

	s := fmt.Sprintf("agi_channel: SIP/%s\nagi_uniqueid: %s\nagi_dnid: %s\n\n", m.NameFrom("Contact"), uniqueid, m.NameFrom("Request"))
	fmt.Fprint(conn, s)
	if *debug {
		fmt.Println(">>", addr)
		fmt.Println(s)
	}

	if ret, err = bufio.NewReader(conn).ReadString('\n'); err == nil {
		s = "200 result=1\n\n"
		fmt.Fprint(conn, s)
		if *debug {
			fmt.Println("<<", addr)
			fmt.Println(ret)
			fmt.Println(">>", addr)
			fmt.Println(s)
		}
	}

	return
}

func (m SIP) Digest(secret string) string {
	// HA1=MD5(username:realm:password) HA2=MD5(method:digestURI) response=MD5(HA1:nonce:HA2)
	b1 := []byte(m.ValueFrom("Authorization", "username") + ":" + m.ValueFrom("Authorization", "realm") + ":" + secret)
	h1 := fmt.Sprintf("%x", md5.Sum(b1))

	b2 := []byte(m.MethodFrom("Request") + ":" + m.ValueFrom("Authorization", "uri"))
	h2 := fmt.Sprintf("%x", md5.Sum(b2))

	b3 := []byte(h1 + ":" + m.ValueFrom("Authorization", "nonce") + ":" + h2)
	return fmt.Sprintf("%x", md5.Sum(b3))
}

func (m SIP) CheckIP(addr net.IP, acl string) bool {
	for _, cidr := range strings.Split(acl, ",") {
		if _, network, err := net.ParseCIDR(cidr); err == nil && network.Contains(addr) {
			return true
		}
	}

	return acl == ""
}

func (m SIP) CheckDialplan(dialplan string) bool {
	if re, err := regexp.Compile(dialplan); err == nil {
		return re.MatchString(strings.TrimPrefix(m.NameFrom("Request"), "8"))
	}

	return dialplan == ""
}

func (m SIP) RandHexString(length int) (s string) {
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		return
	}

	s = fmt.Sprintf("%x", buf)

	return
}

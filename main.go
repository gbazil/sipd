// Copyright (c) 2018 Vasily Suvorov, http://bazil.pro <gbazil@gmail.com>
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.
//

package main

import (
	"database/sql"
	"flag"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"math/rand"
	"net"
	"os"
	"regexp"
	"strings"
)

const (
	appname      = "sipd 1.0.0"
	copyright    = "(c) Vasily Suvorov <gbazil@gmail.com>"
	callidsuffix = "7A7"
)

const schema = `
CREATE table IF NOT EXISTS register (
	name TEXT UNIQUE,
	secret TEXT,
	addr TEXT,
	acode TEXT,
	exten TEXT,
	callerid TEXT,
	dialplan TEXT,
	acl TEXT
);

CREATE table IF NOT EXISTS cdr (
	callid TEXT UNIQUE,
	src TEXT,
	callerid TEXT,
	acode TEXT,
	dst TEXT,
	request TEXT,
	ts1 INTEGER,
	ts2 INTEGER,
	ts3 INTEGER,
	saddr TEXT,
	daddr TEXT,
	fromtag TEXT,
	totag TEXT
);

CREATE table IF NOT EXISTS chain (
	key TEXT UNIQUE,
	val TEXT
);
`

var bindaddr *string
var conn *net.UDPConn
var db *sql.DB
var debug *bool

func main() {
	// CLI args
	about := flag.Bool("a", false, "print about")
	basedir := flag.String("s", ".", "base `directory`")
	bindaddr = flag.String("b", "127.0.0.1:5060", "listen `address`")
	countrycode := flag.String("c", "7", "current country `code`")
	citycode := flag.String("cc", "495", "current city `code`")
	debug = flag.Bool("d", false, "debug mode")
	reload := flag.Bool("r", false, "reload data from sip.conf")
	version := flag.Bool("v", false, "print name, version of the program, current hostname")

	flag.Parse()

	realm, _ := os.Hostname()
	os.Chdir(*basedir)

	if *about {
		fmt.Printf("%s - Light SIP PBX\n%s\n", appname, copyright)
		return
	}

	if *version {
		fmt.Println(appname, "@", realm)
		return
	}

	db, _ = sql.Open("sqlite3", "sipd.sqlite3")
	if _, err := db.Exec(schema); err != nil {
		panic(err)
	}

	defer db.Close()

	Conf2DB()
	if *reload {
		return
	}

	if listenaddr, err := net.ResolveUDPAddr("udp", *bindaddr); err != nil {
		panic(err)
	} else if conn, err = net.ListenUDP("udp", listenaddr); err != nil {
		panic(err)
	}

	defer conn.Close()

	buf := make([]byte, 5000)
	via := "SIP/2.0/UDP " + *bindaddr

	for {
		n, saddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}

		if *debug {
			fmt.Printf("<< %s\n%s\n", saddr, buf[:n])
		}

		// echo response
		if n < 50 {
			conn.WriteToUDP(buf[:n], saddr)
			if *debug {
				fmt.Printf(">> %s\n%s\n", saddr, buf[:n])
			}
			continue
		}

		m := make(SIP) // recreate map SIP
		m.Parse(string(buf[:n]))

		if m["User-Agent"] != "" {
			m["User-Agent"] = appname
		}

		switch m.MethodFrom("Request") {
		case "REGISTER":
			if m["Authorization"] == "" {
				m["Request"] = "SIP/2.0 401 Unauthorized"
				m["WWW-Authenticate"] = fmt.Sprintf(`Digest algorithm=MD5, realm="%s", nonce="%s"`, realm, m.RandHexString(4))
			} else {
				var name, secret, acl string
				db.QueryRow("SELECT name, secret, acl FROM register WHERE name = $1", m.ValueFrom("Authorization", "username")).Scan(&name, &secret, &acl)
				if secret == "" || !m.CheckIP(saddr.IP, acl) || m.ValueFrom("Authorization", "response") != m.Digest(secret) {
					m["Request"] = "SIP/2.0 403 Forbidden"
				} else {
					m["Request"] = "SIP/2.0 200 OK"
					if m["Expires"] == "0" || strings.Contains(m["Contact"], "expires=0") {
						db.Exec("UPDATE register SET addr = '' WHERE name = $1", name)
					} else {
						db.Exec("UPDATE register SET addr = $1 WHERE name = $2", m.AddrFrom("Contact"), name)
					}
				}

				delete(m, "Authorization")
			}

			m.Reply(saddr)

		case "INVITE":
			// AAA
			var acode, callerid, dialplan, acl string
			err = db.QueryRow("SELECT acode, callerid, dialplan, acl FROM register WHERE addr = $1",
				m.AddrFrom("Via")).Scan(&acode, &callerid, &dialplan, &acl)
			if err != nil || !m.CheckIP(saddr.IP, acl) {
				m["Request"] = "SIP/2.0 403 Forbidden"
				m.Reply(saddr)
				continue
			}

			// re-INVITE check
			var addr, dst string
			db.QueryRow("SELECT saddr FROM cdr WHERE instr($1, callid) AND ts2 IS NOT NULL", m["Call-ID"]).Scan(&addr)
			if addr != "" {
				if addr == saddr.String() {
					db.QueryRow("SELECT daddr, dst FROM cdr WHERE instr($1, callid)", m["Call-ID"]).Scan(&addr, &dst)
					m.NameFor("Request", dst)
					m.NameFor("To", dst)
				}
				m["Via"] = via + "," + m["Via"] // shift Via
				m.AddrFor("Request", addr)
				m.AddrFor("Contact", *bindaddr)
				m.Send(addr)
				continue
			}

			// pickup
			if m.NameFrom("Request") == "*11" {
				var callid, fromtag, totag string
				db.QueryRow("SELECT callid, saddr, cdr.callerid, fromtag, totag FROM cdr, register WHERE daddr = addr AND register.acode = $1 AND ts2 IS NULL",
					acode).Scan(&callid, &addr, &dst, &fromtag, &totag)
				if addr != "" {
					m.NameFor("Request", dst)
					m.AddrFor("Request", addr)
					m.NameFor("To", dst)
					m["Replaces"] = fmt.Sprintf("%s;to-tag=%s;from-tag=%s;early-only", callid, totag, fromtag) // early-only;100rel;
					m["Via"] = via + "," + m["Via"]
					m.Send(addr)
					continue
				}
			}

			// services
			var exten string
			if strings.HasPrefix(m.NameFrom("Request"), "*") {
				if !m.CheckDialplan(dialplan) {
					m["Request"] = "SIP/2.0 503 Service Unavailable"
					m.Reply(saddr)
				} else {
					name := m.NameFrom("Contact")
					cmd := m.NameFrom("Request")
					db.QueryRow("SELECT exten FROM register WHERE name = $1", name).Scan(&exten)
					switch {
					case cmd == "*55":
						// just music
					case cmd == "*73": // delete any call forward
						go m.AgiSend()
						exten = regexp.MustCompile(`[=~].*`).ReplaceAllString(exten, "")
						db.Exec("UPDATE register SET exten = $1 WHERE name = $2", exten, name)
					case cmd == "*71" || cmd == "*72": // check call forward
						if forward := regexp.MustCompile(`[=~]\d+`).FindString(exten); forward == "" {
							m.NameFor("Request", "*73")
						} else if forward[0] == '~' {
							m.NameFor("Request", "*71"+forward[1:])
						} else if forward[0] == '=' {
							m.NameFor("Request", "*72"+forward[1:])
						}
					case strings.HasPrefix(cmd, "*71") && len(cmd) == 13: // setup indirect call forward
						go m.AgiSend()
						exten = regexp.MustCompile(`[=~].*`).ReplaceAllString(exten, "")
						db.Exec("UPDATE register SET exten = $1 WHERE name = $2", exten+"~"+cmd[3:], name)
					case strings.HasPrefix(cmd, "*72") && len(cmd) == 13: // setup direct call forward
						go m.AgiSend()
						exten = regexp.MustCompile(`[=~].*`).ReplaceAllString(exten, "")
						db.Exec("UPDATE register SET exten = $1 WHERE name = $2", exten+"="+cmd[3:], name)
					case strings.HasPrefix(cmd, "*7") || strings.HasPrefix(cmd, "*1"):
						m.NameFor("Request", "*70") // wrong forwarding reply
					default:
						m.NameFor("Request", "*00") // invalid number
					}

					db.QueryRow("SELECT addr FROM register WHERE acode = 'mediagates'").Scan(&addr)
					if addr == "" {
						m["Request"] = "SIP/2.0 410 Gone"
						m.Reply(saddr)
					} else {
						m["Via"] = via + "," + m["Via"] // shift Via
						m.AddrFor("Request", addr)
						m.AddrFor("Contact", *bindaddr)
						m.Send(addr)
					}
				}

				continue
			}

			// to realm or call transfer
			var name string
			err = db.QueryRow("SELECT name, addr, exten, callerid FROM register WHERE name = $1 OR (length($1) > 4 AND exten LIKE $1 || '%') OR (length($1) == 4 AND acode == $2 AND (exten LIKE $1 || '%' OR exten LIKE '%#' || $1 || '%'))",
				m.NameFrom("Request"), acode).Scan(&name, &addr, &exten, &callerid)
			if err != sql.ErrNoRows {
				// call transfer to any gate with current callerid
				if s := regexp.MustCompile(`=\d{10}`).FindString(exten); s != "" {
					m.NameFor("Request", "8"+s[1:])
				} else {
					if addr != "" {
						m["Via"] = via + "," + m["Via"] // shift Via
						m.NameFor("Request", name)
						m.AddrFor("Request", addr)
						m.NameFor("To", name)
						m.AddrFor("Contact", *bindaddr)
						m.Send(addr)
					} else {
						m["Request"] = "SIP/2.0 606 Not Acceptable"
						m.Reply(saddr)
					}
					continue
				}
			}

			// for indirect forwarding
			if clid := m.ValueFrom("Request", "clid"); clid != "" {
				callerid = clid
			}

			// aim by AGI
			if callerid == "" {
				// `EXEC TRANSFER "SIP/4956600126@83.102.205.31"`
				if transfer := regexp.MustCompile(`\d+@[0-9.:]+`).FindString(m.AgiSend()); transfer != "" {
					if !strings.Contains(transfer, ":") {
						transfer += ":5060"
					}

					m["Request"] = "SIP/2.0 302 Moved Temporarily"
					m["Contact"] = fmt.Sprintf("Transfer <sip:%s>", transfer)
				} else {
					m["Request"] = "SIP/2.0 404 Not Found"
				}

				m.Reply(saddr)
				continue
			}

			// to gate
			if gw := regexp.MustCompile(`GW\d+$`).FindString(acode); gw != "" { // international496
				db.QueryRow("SELECT addr, '666598' FROM register WHERE name = $1", gw).Scan(&addr, &exten)
			} else {
				var i int
				db.QueryRow("SELECT count(*) FROM register WHERE acode = 'gateways' AND exten != ''").Scan(&i)
				if i > 0 {
					db.QueryRow("SELECT addr, exten FROM register WHERE acode = 'gateways' AND exten != '' LIMIT 1 OFFSET $1",
						rand.Intn(i)).Scan(&addr, &exten)
				}
			}

			if addr == "" {
				m["Request"] = "SIP/2.0 404 Not Found"
			} else if !m.CheckDialplan(dialplan) {
				m["Request"] = "SIP/2.0 403 Forbidden"
			} else {
				number := m.NameFrom("Request")
				// call number in ABC format
				if exten != "9" {
					number = strings.TrimPrefix(number, "8") // sity legacy
					if len(number) > 10 {
						number = strings.TrimPrefix(number, "10") // international legacy
					} else if len(number) > 9 {
						number = *countrycode + number
					} else {
						number = *countrycode + *citycode + number
					}
				}

				m["Via"] = via + "," + m["Via"] // shift Via
				m.NameFor("Request", exten+number)
				m.AddrFor("Request", addr)
				m.NameFor("To", exten+number)
				m.NameFor("From", callerid) // set callerid
				m.AddrFor("Contact", *bindaddr)
				m.Send(addr)
				continue
			}

			m.Reply(saddr)

		case "SIP/2.0":
			// unshift self via (self via may be modified by UAC)
			m["Via"] = regexp.MustCompile(`^[^,]*,`).ReplaceAllString(m["Via"], "")

			// CDR managementf and indirect forwarding
			callid := strings.TrimSuffix(m["Call-ID"], callidsuffix)
			if strings.Contains(m["CSeq"], "INVITE") {
				switch regexp.MustCompile(`\d{3}`).FindString(m["Request"]) {
				case "100": // Trying
					db.Exec("INSERT OR IGNORE INTO cdr VALUES ($1, (SELECT name FROM register WHERE addr = $2), $3, (SELECT acode FROM register WHERE addr = $2), $4, $5, strftime('%s', 'now'), NULL, NULL, $6, $7, '', '')",
						callid, m.AddrFrom("Via"), m.NameFrom("From"), m.NameFrom("To"), m["Request"], m.AddrFrom("Via"), saddr.String())
				case "180", "183": // Ringing or Session Progress
					db.Exec("UPDATE cdr SET request = $1, fromtag = $2, totag = $3, dst = $4, daddr = $5 WHERE callid = $6",
						m["Request"], m.ValueFrom("From", "tag"), m.ValueFrom("To", "tag"), m.NameFrom("To"), saddr.String(), callid)
				case "200": // Ok
					db.Exec("UPDATE cdr SET request = $1, ts2 = strftime('%s', 'now') WHERE callid = $2 AND ts2 IS NULL", m["Request"], callid)
				case "480", "486", "603": // Temporarily Unavailable, Busy Here, Decline
					var name, exten, callerid string
					db.QueryRow("SELECT name, exten, callerid FROM register WHERE addr = $1", saddr.String()).Scan(&name, &exten, &callerid)
					if s := regexp.MustCompile(`~\d{10}`).FindString(exten); s != "" {
						m["Request"] = "SIP/2.0 302 Moved Temporarily"
						m["Contact"] = fmt.Sprintf("<sip:8%s@%s;clid=%s>", s[1:], *bindaddr, callerid)
					} else if db.QueryRow("SELECT val FROM chain WHERE key = $1", name).Scan(&s); s != "" && s != m.NameFrom("From") {
						m["Request"] = "SIP/2.0 302 Moved Temporarily"
						m["Contact"] = fmt.Sprintf("<sip:%s@%s>", s, *bindaddr)
					} else {
						db.Exec("UPDATE cdr SET request = $1, ts2 = strftime('%s', 'now'), ts3 = strftime('%s', 'now') WHERE callid = $2", m["Request"], callid)
					}
				default:
					db.Exec("UPDATE cdr SET request = $1, ts2 = strftime('%s', 'now'), ts3 = strftime('%s', 'now') WHERE callid = $2", m["Request"], callid)
				}
			} else if strings.Contains(m["CSeq"], "BYE") && strings.Contains(m["Request"], "200") {
				db.Exec("UPDATE cdr SET request = $1, ts3 = strftime('%s', 'now') WHERE callid = $2", m["Request"], callid)
			}

			m.AddrFor("Contact", *bindaddr)
			m.Send(m.AddrFrom("Via"))

		default:
			var addr, dst string
			db.QueryRow("SELECT daddr, dst FROM cdr WHERE callid = $1", m["Call-ID"]).Scan(&addr, &dst)
			if addr == "" {
				if db.QueryRow("SELECT saddr FROM cdr WHERE callid = $1", strings.TrimSuffix(m["Call-ID"], callidsuffix)).Scan(&addr); addr == "" {
					continue
				}
			} else {
				m.NameFor("Request", dst)
				m.NameFor("To", dst)
				if clid := m.ValueFrom("Request", "clid"); clid != "" {
					m.NameFor("From", clid)
				}
			}

			m.AddrFor("Request", addr)
			m.AddrFor("Contact", *bindaddr)
			m["Via"] = via + "," + m["Via"] // shift Via
			m.Send(addr)

		}
	}
}

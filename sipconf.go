// Copyright (c) 2018 Vasily Suvorov, http://bazil.pro <gbazil@gmail.com>
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.
//

package main

import (
	"fmt"
	"io/ioutil"
	"regexp"
	"strconv"
	"strings"
)

func str2arr(str string) []int {
	var a []int

	for _, s := range strings.Split(str, ",") {
		i, err := strconv.Atoi(s)
		if err != nil {
			sa := strings.Split(s, "-")
			if len(sa) == 2 {
				x, err := strconv.Atoi(sa[0])
				if err != nil {
					continue
				}

				y, err := strconv.Atoi(sa[1])
				if err != nil {
					continue
				}

				for z := x; z <= y; z++ {
					a = append(a, z)
				}
			}
		} else {
			a = append(a, i)
		}
	}

	return a
}

func Conf2DB() {
	buf, err := ioutil.ReadFile("sip.conf")
	if err != nil {
		return
	}

	sqltext := "BEGIN;\nDELETE FROM register;\n"
	for _, bulk := range strings.Split(string(buf), "\n[") {
		name := strings.TrimSuffix(regexp.MustCompile(`^\S+]`).FindString(bulk), "]")
		if name != "" {
			if name == "general" {
				continue
			}

			exten := strings.TrimPrefix(regexp.MustCompile(`(?m)^exten=\S*`).FindString(bulk), "exten=")
			acode := strings.TrimPrefix(regexp.MustCompile(`(?m)^accountcode=\S*`).FindString(bulk), "accountcode=")
			secret := strings.TrimPrefix(regexp.MustCompile(`(?m)^secret=\S*`).FindString(bulk), "secret=")
			acl := strings.TrimPrefix(regexp.MustCompile(`(?m)^acl=\S*`).FindString(bulk), "acl=")

			addr := strings.TrimPrefix(regexp.MustCompile(`(?m)^host=[0-9.:]*`).FindString(bulk), "host=")
			if addr == "" {
				// live user registered addr
				db.QueryRow("SELECT addr FROM register WHERE name = $1 AND secret = $2", name, secret).Scan(&addr)
			} else {
				if !strings.Contains(addr, ":") {
					addr += ":5060"
				}
			}

			callerid := strings.TrimPrefix(regexp.MustCompile(`(?m)^callerid=.*$`).FindString(bulk), "callerid=")
			if d10 := regexp.MustCompile(`\d{10}`).FindString(callerid); d10 != "" {
				callerid = d10
			}

			dialplan := strings.TrimPrefix(regexp.MustCompile(`(?m)^dialplan=\S*`).FindString(bulk), "dialplan=")
			if dialplan == "" {
				switch strings.TrimPrefix(regexp.MustCompile(`(?m)^context=\S*`).FindString(bulk), "context=") {
				case "domestic":
					dialplan = `^.{2,10}$|^\*.{2,12}$` // 10 R CCC 1234567 = 13
				case "mobile":
					dialplan = `^9.|^49[59]|^800|^.{2,3}$`
				case "local":
					dialplan = `^49[59]|^800|^.{2,3}$`
				case "trush", "em":
					dialplan = `^.{2,3}$`
				}
			}

			sqltext += fmt.Sprintf("INSERT INTO register VALUES ('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s');\n",
				name, secret, addr, acode, exten, callerid, dialplan, acl)
		}
	}

	var final string
	if _, err := db.Exec(sqltext); err != nil {
		final = "ROLLBACK;\n"
	} else {
		final = "COMMIT\n"
	}

	db.Exec(final)

	if *debug {
		fmt.Println(sqltext + final)
	}

	// compose indirect call forward chains (serial call)
	sqltext = "DELETE FROM chain;\n"
	rows, _ := db.Query("SELECT name, acode, exten FROM register ORDER BY acode, name")
	for rows.Next() {
		var name, acode, exten string
		if err := rows.Scan(&name, &acode, &exten); err != nil {
			continue
		}

		if serial := regexp.MustCompile(`\([^)]+`).FindString(exten); serial != "" {
			for _, i := range str2arr(strings.TrimPrefix(serial, "(")) {
				key := name
				err := db.QueryRow("SELECT name FROM register WHERE acode = $1 ORDER BY acode, name LIMIT 1 OFFSET $2 - 1", acode, i).Scan(&name)
				if err == nil {
					sqltext += fmt.Sprintf("REPLACE INTO chain VALUES ('%s', '%s');\n", key, name)
				}
			}
		}
	}

	db.Exec(sqltext)
	if *debug {
		fmt.Println(sqltext)
	}
}

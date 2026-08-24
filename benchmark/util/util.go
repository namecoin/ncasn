/*
Copyright (C) Namecoin

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

package util

import (
	"cmp"
	"unicode"

	"github.com/miekg/dns"
	"github.com/sofia-nep/ncasn"
)

func IsAscii(str string) bool {
	for _, c := range str {
		if c > unicode.MaxASCII {
			return false
		}
	}

	return true
}

func SplitTxt(record string) []string {
	var parts []string

	started := false
	startedAt := 0
	for i, c := range record {
		if !started && c == ' ' {
			continue
		}

		if c == '"' {
			started = !started

			if started {
				startedAt = i + 1
			} else {
				parts = append(parts, record[startedAt:i])
			}
		}
	}

	return parts
}

func CmpRecords(a ncasn.Record, b ncasn.Record) int {
	return cmp.Compare(*a.Name, *b.Name)
}

func TypeFromUnion(union *ncasn.RecordUnion) uint16 {
	var ret uint16
	switch {
	case union.A != nil:
		ret = dns.TypeA
	case union.AAAA != nil:
		ret = dns.TypeAAAA
	case union.Srv != nil:
		ret = dns.TypeSRV
	case union.Ds != nil:
		ret = dns.TypeDS
	case union.Txt != nil:
		ret = dns.TypeTXT
	case union.Tlsa != nil:
		ret = dns.TypeTLSA
	case union.Loc != nil:
		ret = dns.TypeLOC
	case union.Mx != nil:
		ret = dns.TypeMX
	case union.Sshfp != nil:
		ret = dns.TypeSSHFP
	case union.Generic != nil:
		ret = union.Generic.Type
	default:
		ret = 0
	}

	return ret
}

type TorRecords struct {
	Data    []string
	Ignored []*ncasn.Record
}

type CborRecords struct {
	Data    []byte
	Ignored []*ncasn.Record
}

type Zone struct {
	Zone *ncasn.Zone
	Json string
	Cbor *CborRecords
	Tor  *TorRecords
}

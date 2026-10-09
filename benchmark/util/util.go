/*
Copyright (C) Namecoin developers

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
	"slices"
	"strings"
	"unicode"

	"github.com/miekg/dns"
	"github.com/namecoin/ncasn"
	"github.com/namecoin/ncasn/contrasub"
)

type GenericNameRecord struct {
	Name       string
	RecordData ncasn.RecordUnion
}

func (record *GenericNameRecord) ToHidden() ncasn.HiddenDomainRecord {
	return contrasub.NewHiddenDomainRecord(record.Name, &record.RecordData)
}

func (record *GenericNameRecord) ToVisible() ncasn.VisibleDomainRecord {
	return ncasn.VisibleDomainRecord{
		Name:       &record.Name,
		RecordData: record.RecordData,
	}
}

func IsAscii(str string) bool {
	for _, c := range str {
		if c > unicode.MaxASCII {
			return false
		}
	}

	return true
}

func isNsGlue(record *GenericNameRecord, ns []GenericNameRecord, base string) *string {
	if record.RecordData.A == nil && record.RecordData.AAAA == nil {
		return nil
	}

	for _, elem := range ns {
		if elem.RecordData.Ns.String == nil {
			continue
		}

		target := strings.TrimSuffix(*elem.RecordData.Ns.String, ".")
		target = strings.TrimSuffix(target, "."+base)
		if target == record.Name {
			return elem.RecordData.Ns.String
		}
	}

	return nil
}

func CollapseNsGlues(records []GenericNameRecord, base string) []GenericNameRecord {
	var ns []GenericNameRecord

	for _, record := range records {
		if record.RecordData.Ns != nil {
			ns = append(ns, record)
		}
	}

	if ns == nil {
		return records
	}

	ret := []GenericNameRecord{}
	for _, record := range records {
		if record.RecordData.Ns != nil {
			continue
		}

		target := isNsGlue(&record, ns, base)
		if target == nil {
			ret = append(ret, record)
			continue
		}

		ns = slices.DeleteFunc(ns, func(record GenericNameRecord) bool {
			return *record.RecordData.Ns.String == *target
		})

		var union ncasn.RecordUnion
		if record.RecordData.A != nil {
			union = ncasn.RecordUnion{
				Ns: &ncasn.NS{
					Ip: &ncasn.NSIP{
						A: record.RecordData.A,
					},
				},
			}
		} else {
			union = ncasn.RecordUnion{
				Ns: &ncasn.NS{
					Ip: &ncasn.NSIP{
						AAAA: record.RecordData.AAAA,
					},
				},
			}
		}

		ret = append(ret, GenericNameRecord{
			Name:       record.Name,
			RecordData: union,
		})
	}

	ret = append(ret, ns...)

	return ret
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

func CmpRecords(a GenericNameRecord, b GenericNameRecord) int {
	return cmp.Compare(a.Name, b.Name)
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
	Ignored []*GenericNameRecord
}

type CborRecords struct {
	Data    []byte
	Ignored []*GenericNameRecord
}

type GenericZone struct {
	Info    *ncasn.Whois
	Records []GenericNameRecord
}

type Zone struct {
	Zone     *GenericZone
	Json     string
	Cbor     *CborRecords
	Tor      *TorRecords
	Coverage float64
}

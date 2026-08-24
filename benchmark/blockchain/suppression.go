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

package blockchain

import (
	"strings"

	"github.com/miekg/dns"
	"github.com/sofia-nep/ncasn"
)

func notDns(union *ncasn.RecordUnion) bool {
	return union.Onion != nil || union.I2p != nil || union.I2pLs2 != nil || union.Ipns != nil || union.Hyphanet != nil
}

func sameLevel(record *ncasn.Record, list []ncasn.Record) bool {
	for _, elem := range list {
		if *record.Name == *elem.Name {
			return true
		}
	}

	return false
}

func isGlue(record *ncasn.Record, ns []ncasn.Record) bool {
	if record.RecordData.A == nil && record.RecordData.AAAA == nil {
		return false
	}

	for _, elem := range ns {
		if elem.RecordData.Generic.Target == *record.Name {
			return true
		}
	}

	return false
}

func higherLevel(record *ncasn.Record, records []ncasn.Record) bool {
	for _, baseRec := range records {
		if *record.Name == *baseRec.Name || strings.HasSuffix(*record.Name, "."+*baseRec.Name) {
			return false
		}
	}

	return true
}

func suppressNs(records []ncasn.Record) []ncasn.Record {
	var ret []ncasn.Record
	ns := []ncasn.Record{}

	for _, record := range records {
		if record.RecordData.Generic != nil && record.RecordData.Generic.Type == dns.TypeNS {
			ns = append(ns, record)
		}
	}

	for _, record := range records {
		switch {
		case notDns(&record.RecordData):
			fallthrough
		case higherLevel(&record, ns):
			ret = append(ret, record)
		case sameLevel(&record, ns):
			if (record.RecordData.Generic != nil && record.RecordData.Generic.Type == dns.TypeNS) || record.RecordData.Ds != nil {
				ret = append(ret, record)
			}
		case isGlue(&record, ns):
			ret = append(ret, record)
		}
	}

	return ret
}

func suppressDname(records []ncasn.Record) []ncasn.Record {
	dname := []ncasn.Record{}
	var ret []ncasn.Record

	for _, record := range records {
		if record.RecordData.Generic != nil && record.RecordData.Generic.Type == dns.TypeDNAME {
			dname = append(dname, record)
		}
	}

	for _, record := range records {
		switch {
		case notDns(&record.RecordData):
			fallthrough
		case higherLevel(&record, dname):
			fallthrough
		case sameLevel(&record, dname) && record.RecordData.Generic != nil && record.RecordData.Generic.Type == dns.TypeDNAME:
			ret = append(ret, record)
		}
	}

	return ret
}

func suppressCname(records []ncasn.Record) []ncasn.Record {
	cname := []ncasn.Record{}
	var ret []ncasn.Record

	for _, record := range records {
		if record.RecordData.Generic != nil && record.RecordData.Generic.Type == dns.TypeCNAME {
			cname = append(cname, record)
		}
	}

	for _, record := range records {
		switch {
		case notDns(&record.RecordData):
			fallthrough
		case !sameLevel(&record, cname):
			fallthrough
		case record.RecordData.Generic != nil && record.RecordData.Generic.Type == dns.TypeCNAME:
			ret = append(ret, record)
		}
	}

	return ret
}

func applySuppression(records []ncasn.Record) []ncasn.Record {
	ret := suppressNs(records)
	ret = suppressDname(ret)
	return suppressCname(ret)
}

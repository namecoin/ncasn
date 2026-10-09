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

package blockchain

import (
	"strings"

	"github.com/namecoin/ncasn"
	"github.com/namecoin/ncasn/benchmark/util"
)

func notDns(union *ncasn.RecordUnion) bool {
	return union.Onion != nil || union.I2p != nil || union.I2pLs2 != nil || union.Ipns != nil || union.Hyphanet != nil
}

func sameLevel(record *util.GenericNameRecord, list []util.GenericNameRecord) bool {
	for _, elem := range list {
		if record.Name == elem.Name {
			return true
		}
	}

	return false
}

func higherLevel(record *util.GenericNameRecord, records []util.GenericNameRecord) bool {
	for _, baseRec := range records {
		if record.Name == baseRec.Name || strings.HasSuffix(record.Name, "."+baseRec.Name) {
			return false
		}
	}

	return true
}

func suppressNs(records []util.GenericNameRecord) []util.GenericNameRecord {
	var ret []util.GenericNameRecord
	ns := []util.GenericNameRecord{}

	for _, record := range records {
		if record.RecordData.Ns != nil {
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
			if record.RecordData.Ns != nil || record.RecordData.Ds != nil {
				ret = append(ret, record)
			}
		}
	}

	return ret
}

func suppressDname(records []util.GenericNameRecord) []util.GenericNameRecord {
	dname := []util.GenericNameRecord{}
	var ret []util.GenericNameRecord

	for _, record := range records {
		if record.RecordData.Dname != nil {
			dname = append(dname, record)
		}
	}

	for _, record := range records {
		switch {
		case notDns(&record.RecordData):
			fallthrough
		case higherLevel(&record, dname):
			fallthrough
		case sameLevel(&record, dname) && record.RecordData.Dname != nil:
			ret = append(ret, record)
		}
	}

	return ret
}

func suppressCname(records []util.GenericNameRecord) []util.GenericNameRecord {
	cname := []util.GenericNameRecord{}
	var ret []util.GenericNameRecord

	for _, record := range records {
		if record.RecordData.Cname != nil {
			cname = append(cname, record)
		}
	}

	for _, record := range records {
		switch {
		case notDns(&record.RecordData):
			fallthrough
		case !sameLevel(&record, cname):
			fallthrough
		case record.RecordData.Cname != nil:
			ret = append(ret, record)
		}
	}

	return ret
}

func applySuppression(records []util.GenericNameRecord) []util.GenericNameRecord {
	ret := suppressNs(records)
	ret = suppressDname(ret)
	return suppressCname(ret)
}

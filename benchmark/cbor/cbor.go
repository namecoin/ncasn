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

package cbor

import (
	"strings"

	"github.com/fxamacker/cbor"
	"github.com/miekg/dns"
	"github.com/sofia-nep/ncasn"
	"github.com/sofia-nep/ncasn/benchmark/util"
	"github.com/sofia-nep/ncasn/benchmark/wire"
)

// See https://datatracker.ietf.org/doc/draft-lenders-dns-cbor, WIP.

func RecordsToCbor(records []ncasn.Record) (*util.CborRecords, error) {
	ignored := []*ncasn.Record{}
	encoded := [][]any{}

	var lastName *string
	for i := range records {
		var encRecord []any
		encRecord, tmpName := recordToCbor(&records[i], lastName)
		if encRecord == nil {
			ignored = append(ignored, &records[i])
		} else {
			lastName = tmpName
			encoded = append(encoded, encRecord)
		}
	}

	cborData, err := cbor.Marshal(encoded, cbor.EncOptions{})
	if err != nil {
		return nil, err
	}

	return &util.CborRecords{Data: cborData, Ignored: ignored}, nil
}

func recordDataToCbor(record *ncasn.RecordUnion) ([]byte, []any) {
	switch {
	case record.Srv != nil:
		ret := []any{record.Srv.Priority}
		if record.Srv.Weight != nil {
			ret = append(ret, *record.Srv.Weight)
		}
		return nil, append(ret, record.Srv.Port, record.Srv.Target)
	case record.Mx != nil:
		return nil, []any{record.Mx.Priority, strings.Split(record.Mx.Target, ".")}
	case record.Import != nil:
		data := []any{record.Import.Name}
		if record.Import.Subdomain != nil {
			data = append(data, *record.Import.Subdomain)
		}

		return nil, data
	default:
		return wire.ToWire(record), nil
	}
}

func recordToCbor(record *ncasn.Record, lastName *string) ([]any, *string) {
	var ret []any
	if lastName == nil || *lastName != *record.Name {
		lastName = record.Name

		if strings.Contains(*record.Name, ".") {
			ret = append(ret, strings.Split(*record.Name, "."))
		} else {
			ret = append(ret, *record.Name)
		}
	}

	ret = append(ret, 0, util.TypeFromUnion(&record.RecordData), dns.ClassINET)

	bytes, arr := recordDataToCbor(&record.RecordData)

	switch {
	case bytes != nil:
		ret = append(ret, bytes)
	case arr != nil:
		ret = append(ret, arr)
	default:
		return nil, lastName
	}

	return ret, lastName
}

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

package cbor

import (
	"fmt"
	"strings"

	"github.com/fxamacker/cbor"
	"github.com/miekg/dns"
	"github.com/namecoin/ncasn"
	"github.com/namecoin/ncasn/benchmark/util"
	"github.com/namecoin/ncasn/benchmark/wire"
)

// See https://datatracker.ietf.org/doc/draft-lenders-dns-cbor, WIP.

func RecordsToCbor(records []util.GenericNameRecord, hidden bool) (*util.CborRecords, error) {
	ignored := []*util.GenericNameRecord{}
	encoded := [][]any{}

	nsIdx := 0
	var lastName *string
	for i := range records {
		var encRecord []any
		encRecord, tmpName := recordToCbor(&records[i], lastName, nsIdx, hidden)
		if encRecord == nil {
			ignored = append(ignored, &records[i])
		} else {
			lastName = tmpName
			encoded = append(encoded, encRecord)
		}

		if records[i].RecordData.Ns != nil && records[i].RecordData.Ns.String == nil {
			nsStr := fmt.Sprint("ns", nsIdx)
			var record []any
			if records[i].RecordData.Ns.Ip.A != nil {
				record, _ = recordToCbor(&util.GenericNameRecord{
					Name: nsStr,
					RecordData: ncasn.RecordUnion{
						A: records[i].RecordData.Ns.Ip.A,
					},
				}, lastName, nsIdx, hidden)
			} else {
				record, _ = recordToCbor(&util.GenericNameRecord{
					Name: nsStr,
					RecordData: ncasn.RecordUnion{
						AAAA: records[i].RecordData.Ns.Ip.AAAA,
					},
				}, lastName, nsIdx, hidden)
			}

			encoded = append(encoded, record)
			nsIdx++
		}
	}

	cborData, err := cbor.Marshal(encoded, cbor.EncOptions{})
	if err != nil {
		return nil, err
	}

	return &util.CborRecords{Data: cborData, Ignored: ignored}, nil
}

func recordDataToCbor(record *ncasn.RecordUnion, nsIdx int) ([]byte, []any) {
	switch {
	case record.Srv != nil:
		ret := []any{record.Srv.Data.Priority}
		if record.Srv.Data.Weight != nil {
			ret = append(ret, *record.Srv.Data.Weight)
		}
		return nil, append(ret, record.Srv.Data.Port, record.Srv.Data.Target)
	case record.Mx != nil:
		return nil, []any{record.Mx.Priority, strings.Split(record.Mx.Target, ".")}
	case record.Import != nil:
		data := []any{record.Import.Name}
		if record.Import.Subdomain != nil {
			data = append(data, *record.Import.Subdomain)
		}

		return nil, data
	case record.Ns != nil && record.Ns.String == nil:
		return wire.DomainToWire(fmt.Sprint("ns", nsIdx)), nil
	default:
		return wire.ToWire(record), nil
	}
}

func recordToCbor(record *util.GenericNameRecord, lastName *string, nsIdx int, hidden bool) ([]any, *string) {
	var ret []any
	name := record.Name

	switch {
	case record.RecordData.Txt != nil && record.RecordData.Txt.DnsWl:
		if len(name) == 0 {
			name = "_token._dnswl"
		} else {
			name = "_token._dnswl." + name
		}
	case record.RecordData.Srv != nil && record.RecordData.Srv.Meta != nil:
		prefix := record.RecordData.Srv.Meta.ToPrefix()
		if len(name) == 0 {
			name = prefix
		} else {
			name = prefix + "." + name
		}
	}

	if lastName == nil || *lastName != name {
		lastName = &name

		switch {
		case hidden:
			ret = append(ret, uint8(0))
		case strings.Contains(name, "."):
			ret = append(ret, strings.Split(name, "."))
		default:
			ret = append(ret, name)
		}
	}

	ret = append(ret, 0, util.TypeFromUnion(&record.RecordData), dns.ClassINET)

	bytes, arr := recordDataToCbor(&record.RecordData, nsIdx)

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

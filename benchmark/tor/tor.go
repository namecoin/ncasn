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

package tor

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
	"github.com/namecoin/ncasn"
	"github.com/namecoin/ncasn/benchmark/util"
	"github.com/namecoin/ncasn/benchmark/wire"
)

func RecordsToTor(records []ncasn.Record) (*util.TorRecords, error) {
	ret := []string{}
	ignored := []*ncasn.Record{}

	var lastName *string
	for i := range records {
		encoded, err := toTor(&records[i].RecordData)
		if err != nil {
			return nil, fmt.Errorf("Failed to convert record to Tor format: %s", err.Error())
		}

		if encoded == nil {
			ignored = append(ignored, &records[i])
		} else {
			prefix := ""
			if lastName == nil || *lastName != *records[i].Name {
				prefix = *records[i].Name + " "
			}

			ret = append(ret, prefix+*encoded)
			lastName = records[i].Name
		}
	}

	return &util.TorRecords{Data: ret, Ignored: ignored}, nil
}

// See https://spec.torproject.org/proposals/343-rend-caa.html

func toTor(record *ncasn.RecordUnion) (*string, error) {
	switch {
	case record.Generic != nil:
		data := record.Generic.Target
		typeOf := record.Generic.Type
		if (typeOf == dns.TypeNS || typeOf == dns.TypeCNAME || typeOf == dns.TypeDNAME) && !strings.HasSuffix(data, ".") {
			data += "."
		}

		ret := strings.ToLower(dns.TypeToString[record.Generic.Type]) + " " + data
		return &ret, nil
	case record.Onion != nil:
		ret := "onion " + record.Onion.ToDomain()
		return &ret, nil
	case record.I2p != nil:
		ret := "i2p " + record.I2p.ToDomain()
		return &ret, nil
	case record.I2pLs2 != nil:
		ret := "i2pls2 " + record.I2pLs2.ToDomain()
		return &ret, nil
	case record.Ipns != nil:
		ret := "ipns " + record.Ipns.ToString()
		return &ret, nil
	case record.Hyphanet != nil:
		ret := "hypha " + record.Hyphanet.ToKey()
		return &ret, nil
	case record.Import != nil:
		fallthrough
	case record.Alias != nil:
		return nil, nil
	default:
		wire := wire.ToWire(record)
		typeOf := util.TypeFromUnion(record)
		dummy := dns.RR_Header{
			Name:     "example.com.",
			Rrtype:   typeOf,
			Class:    dns.ClassINET,
			Ttl:      0,
			Rdlength: uint16(len(wire)),
		}

		encoded, _, err := dns.UnpackRRWithHeader(dummy, wire, 0)
		if err != nil {
			return nil, fmt.Errorf("Failed to convert %s record with rdlength %d to Tor format: %s", dns.TypeToString[typeOf], len(wire), err.Error())
		}

		fields := strings.Fields(encoded.String())

		// Blank data
		if len(fields) < 5 {
			return nil, nil
		}

		ret := strings.ToLower(dns.TypeToString[typeOf]) + " " + strings.Join(fields[4:], " ")

		return &ret, nil
	}
}

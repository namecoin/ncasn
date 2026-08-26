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

package zone

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/miekg/dns"
	"github.com/namecoin/ncasn"
	"github.com/namecoin/ncasn/benchmark/cbor"
	"github.com/namecoin/ncasn/benchmark/tor"
	"github.com/namecoin/ncasn/benchmark/util"
	"github.com/namecoin/ncasn/benchmark/wire"
)

// Both may be nil if the record is ignored
func ParseRecord(line string, zone bool) (*ncasn.Record, error) {
	fields := strings.Fields(line)

	if len(fields) == 0 {
		return nil, errors.New("Invalid record: no domain")
	}

	parts := strings.Split(fields[0], ".")
	subdomain := strings.Join(parts[:len(parts)-2], ".")
	if len(fields) < 5 {
		return nil, errors.New("Invalid record: no type/data")
	}
	typeName := fields[3]

	var union *ncasn.RecordUnion
	// Not exhaustive, but works with the current sample
	switch typeName {
	case "A":
		ip := net.ParseIP(fields[4])
		if ip == nil {
			return nil, fmt.Errorf("Invalid A record: %s", fields[4])
		}

		ip = ip.To4()
		if ip == nil {
			return nil, errors.New("IPv6 should be IPv4")
		}

		union = &ncasn.RecordUnion{A: &ncasn.A{Target: ip}}
	case "AAAA":
		ip := net.ParseIP(fields[4])
		if ip == nil {
			return nil, fmt.Errorf("Invalid AAAA record: %s", fields[4])
		}
		union = &ncasn.RecordUnion{AAAA: &ncasn.AAAA{Bytes: ip}}
	case "SRV":
		var err error
		union, err = parseSrv(fields)
		if err != nil {
			return nil, err
		}
	case "DS":
		var err error
		union, err = parseDs(fields)
		if err != nil {
			return nil, err
		}
	case "TXT":
		data := strings.Join(fields[4:], " ")

		if len(data) > 4096 {
			return nil, nil
		}

		union = &ncasn.RecordUnion{Txt: &ncasn.TXT{
			Content: data,
		}}
	case "MX":
		if len(fields) < 6 {
			return nil, errors.New("Missing MX record priority/target")
		}

		priority, err := strconv.ParseUint(fields[4], 10, 16)
		if err != nil {
			return nil, fmt.Errorf("Invalid MX priority: %s", err.Error())
		}

		union = &ncasn.RecordUnion{
			Mx: &ncasn.MX{Priority: uint16(priority), Target: fields[5]},
		}
	case "SSHFP":
		if len(fields) < 7 {
			return nil, errors.New("Missing SSHFP fields")
		}

		keyAlgo, err := strconv.ParseUint(fields[4], 10, 3)
		if err != nil {
			return nil, fmt.Errorf("Failed to parse SSHFP key algo: %s", err.Error())
		}
		if keyAlgo < 4 {
			fmt.Printf("SSHFP key algo %d is not supported\n", keyAlgo)
			return nil, nil
		}

		hashAlgo, err := strconv.ParseUint(fields[5], 10, 2)
		if err != nil {
			return nil, fmt.Errorf("Failed to parse SSHFP hash algo: %s", err.Error())
		}

		if hashAlgo != 2 {
			fmt.Printf("SSHFP hash algo %d is not supported\n", hashAlgo)
			return nil, nil
		}

		bytes, err := hex.DecodeString(fields[6])
		if err != nil {
			return nil, err
		}

		length := len(bytes)
		if length != 32 {
			return nil, fmt.Errorf("Invalid SSHFP fingerprint length %d", length)
		}

		union = &ncasn.RecordUnion{
			Sshfp: &ncasn.SSHFP{KeyAlgoIndex: uint8(keyAlgo) - 4, Fingerprint: bytes},
		}
	case "CNAME", "HTTPS", "NS":
		union = &ncasn.RecordUnion{
			Generic: &ncasn.Generic{Type: dns.StringToType[typeName], Target: strings.Join(fields[4:], " ")},
		}
	case "SOA", "NSEC3", "NSEC3PARAM", "DNSKEY", "RRSIG", "CDS", "CDNSKEY", "CAA":
		if zone {
			return nil, nil
		}

		union = &ncasn.RecordUnion{
			Generic: &ncasn.Generic{Type: dns.StringToType[typeName], Target: strings.Join(fields[4:], " ")},
		}
	}

	if union == nil {
		fmt.Println("Unsupported record:", strings.Join(fields, " "))
		return nil, nil
	}

	return &ncasn.Record{Name: &subdomain, RecordData: *union}, nil
}

func addRecord(record *ncasn.RecordUnion, obj map[string]any) {
	switch {
	case record.A != nil:
		ip, found := obj["ip"]
		var ipCast []string
		if found {
			ipCast = ip.([]string)
		}

		obj["ip"] = append(ipCast, net.IP(record.A.Target).String())
	case record.AAAA != nil:
		ip6, found := obj["ip6"]
		var ip6Cast []string
		if found {
			ip6Cast = ip6.([]string)
		}

		obj["ip6"] = append(ip6Cast, net.IP(record.AAAA.Bytes).String())
	case record.Srv != nil:
		srv, found := obj["srv"]
		var srvCast [][]any
		if found {
			srvCast = srv.([][]any)
		}

		var weight uint16
		if record.Srv.Weight == nil {
			weight = 0
		} else {
			weight = *record.Srv.Weight
		}

		obj["srv"] = append(srvCast, []any{record.Srv.Priority, weight, record.Srv.Port, record.Srv.Target})
	case record.Ds != nil:
		ds, found := obj["ds"]
		var dsCast [][]any
		if found {
			dsCast = ds.([][]any)
		}

		digestUnion := record.Ds.Digest
		var digest []byte
		switch {
		case digestUnion.Sha256 != nil:
			digest = *digestUnion.Sha256
		case digestUnion.Sha384 != nil:
			digest = *digestUnion.Sha384
		case digestUnion.Unassigned7 != nil:
			digest = *digestUnion.Unassigned7
		case digestUnion.Unassigned8 != nil:
			digest = *digestUnion.Unassigned8
		}

		obj["ds"] = append(dsCast,
			[]any{
				record.Ds.KeyTag,
				record.Ds.GetKeyAlgorithm(),
				digestUnion.GetType(),
				base64.StdEncoding.EncodeToString(digest),
			},
		)
	case record.Txt != nil:
		txt, found := obj["txt"]
		var txtCast [][]string
		if found {
			txtCast = txt.([][]string)
		}

		parts := util.SplitTxt(record.Txt.Content)
		obj["txt"] = append(txtCast, parts)
	case record.Tlsa != nil:
		tls, found := obj["tls"]
		var tlsCast [][]any
		if found {
			tlsCast = tls.([][]any)
		}

		data := record.Tlsa.AssociationData
		var bytes []byte
		switch {
		case data.Sha256 != nil:
			bytes = *data.Sha256
		case data.Sha512 != nil:
			bytes = *data.Sha512
		case data.Unassigned0 != nil:
			bytes = *data.Unassigned0
		case data.Unassigned1 != nil:
			bytes = *data.Unassigned1
		}

		// 2 = DANE-TA
		obj["tls"] = append(tlsCast, []any{uint8(2), record.Tlsa.Selector, data.GetMatchingType(), base64.StdEncoding.EncodeToString(bytes)})
	case record.Loc != nil:
		loc, found := obj["loc"]
		var locCast []string
		if found {
			locCast = loc.([]string)
		}

		obj["loc"] = append(locCast, record.Loc.String())
	case record.Sshfp != nil:
		sshfp, found := obj["sshfp"]
		var cast [][]any
		if found {
			cast = sshfp.([][]any)
		}

		// 2 = SHA-256
		obj["sshfp"] = append(cast, []any{
			record.Sshfp.GetKeyAlgo(),
			uint8(2),
			base64.StdEncoding.EncodeToString(record.Sshfp.Fingerprint),
		})
	case record.Onion != nil:
		tor, found := obj["tor"]
		var cast []string
		if found {
			cast = tor.([]string)
		}

		obj["tor"] = append(cast, record.Onion.ToDomain())
	case record.I2p != nil:
		i2p, found := obj["i2p"]
		var cast []string
		if found {
			cast = i2p.([]string)
		}

		obj["i2p"] = append(cast, record.I2p.ToDomain())
	case record.I2pLs2 != nil:
		i2p, found := obj["i2p"]
		var cast []string
		if found {
			cast = i2p.([]string)
		}

		obj["i2p"] = append(cast, record.I2pLs2.ToDomain())
	case record.Import != nil:
		imports, found := obj["import"]
		var cast [][]string
		if found {
			cast = imports.([][]string)
		}

		subArr := []string{record.Import.Name}
		if record.Import.Subdomain != nil {
			subArr = append(subArr, *record.Import.Subdomain)
		}

		obj["import"] = append(cast, subArr)
	case record.Hyphanet != nil:
		obj["freenet"] = record.Hyphanet.ToKey()
	case record.Generic != nil:
		switch record.Generic.Type {
		case dns.TypeCNAME:
			obj["alias"] = record.Generic.Target
		case dns.TypeDNAME:
			obj["translate"] = record.Generic.Target
		case dns.TypeNS:
			obj["ns"] = record.Generic.Target
		default: // Unsure if anything in the sample actually reaches this, but it's semantically nice
			generic, found := obj["o"]
			var cast [][]any
			if found {
				cast = generic.([][]any)
			}

			b64 := base64.StdEncoding.EncodeToString(wire.ToWire(record))

			obj["o"] = append(cast, []any{record.Generic.Type, b64})
		}
	}
}

func zoneFromRecords(records []ncasn.Record) (*util.Zone, error) {
	obj := map[string]any{}

	for _, record := range records {
		if len(*record.Name) == 0 {
			addRecord(&record.RecordData, obj)
			continue
		}

		parts := strings.Split(*record.Name, ".")
		slices.Reverse(parts)

		last := obj
		for _, part := range parts {
			mapField, found := last["map"]
			var mapCast map[string]any
			if found {
				mapCast = mapField.(map[string]any)
			} else {
				mapCast = map[string]any{}
				last["map"] = mapCast
			}

			subField, found := mapCast[part]
			var sub map[string]any
			if found {
				sub = subField.(map[string]any)
			} else {
				sub = map[string]any{}
				mapCast[part] = sub
			}

			last = sub
		}

		addRecord(&record.RecordData, last)
	}

	str, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}

	ret := util.Zone{Zone: &ncasn.Zone{Records: records}, Json: string(str)}
	slices.SortFunc(ret.Zone.Records, util.CmpRecords)
	ret.Cbor, err = cbor.RecordsToCbor(records)
	if err != nil {
		return nil, err
	}

	ret.Tor, err = tor.RecordsToTor(records)
	if err != nil {
		return nil, fmt.Errorf("Failed to convert zone records to Tor format: %s", err.Error())
	}

	return &ret, nil
}

func readZone(filePath string) (*util.Zone, error) {
	fd, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer fd.Close()

	var records []ncasn.Record

	// Primarily used to handle RFC 3597
	parser := dns.NewZoneParser(fd, "", filePath)
	record, ok := parser.Next()
	for ok {
		raw := record.String()
		parsed, err := ParseRecord(raw, true)
		if err != nil {
			return nil, err
		}

		if parsed != nil {
			records = append(records, *parsed)
		}

		record, ok = parser.Next()
	}

	err = parser.Err()
	if err != nil {
		return nil, err
	}

	return zoneFromRecords(records)
}

func ReadZones(dir string) ([]util.Zone, error) {
	files, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var ret []util.Zone
	for _, file := range files {
		fileType := file.Type()
		if !fileType.IsRegular() && fileType != os.ModeSymlink {
			continue
		}

		info, err := file.Info()
		if err != nil {
			return nil, err
		}

		name := info.Name()
		if !strings.HasSuffix(name, ".zone") {
			continue
		}

		zone, err := readZone(dir + "/" + name)
		if err != nil {
			return nil, err
		}

		ret = append(ret, *zone)
	}

	return ret, nil
}

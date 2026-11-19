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

package zone

import (
	"encoding/base64"
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

// ParseRecord's returns may both be nil if the record is ignored.
// nolint: cyclop, funlen
func ParseRecord(line string, zone bool, skipped *int) (*util.GenericNameRecord, error) {
	fields := strings.Fields(line)

	if len(fields) == 0 {
		return nil, errors.New("invalid record: no domain")
	}

	parts := strings.Split(fields[0], ".")

	subdomain := strings.Join(parts[:len(parts)-3], ".")

	metaLen := 5

	if len(fields) < metaLen {
		return nil, errors.New("invalid record: no type/data")
	}

	typeName := fields[3]

	var union *ncasn.RecordUnion
	// Not exhaustive, but works with the current sample
	switch typeName {
	case "A":
		ip := net.ParseIP(fields[4])
		if ip == nil {
			return nil, fmt.Errorf("invalid A record: %s", fields[4])
		}

		ip = ip.To4()
		if ip == nil {
			return nil, errors.New("IPv6 should be IPv4")
		}

		union = &ncasn.RecordUnion{A: &ncasn.A{Target: ip}}
	case "AAAA":
		ip := net.ParseIP(fields[4])
		if ip == nil {
			return nil, fmt.Errorf("invalid AAAA record: %s", fields[4])
		}

		union = &ncasn.RecordUnion{AAAA: &ncasn.AAAA{Bytes: ip}}
	case "SRV":
		var err error

		union, err = parseSrv(fields)
		if err != nil {
			return nil, err
		}

		subdomain = processSrv(subdomain, union.Srv)
	case "DS":
		var err error

		union, err = parseDs(fields)
		if err != nil {
			return nil, err
		}

		if union == nil {
			*skipped++
			data := strings.Join(fields[4:], " ")
			union = &ncasn.RecordUnion{
				Generic: &ncasn.Generic{
					Type:   dns.TypeDS,
					Target: data,
				},
			}
		}
	case "TXT":
		union = parseTxt(fields[4:], &subdomain)
	case "MX":
		recLen := 6
		if len(fields) < recLen {
			return nil, errors.New("missing MX record priority/target")
		}

		priority, err := strconv.ParseUint(fields[4], 10, 16)
		if err != nil {
			return nil, fmt.Errorf("invalid MX priority: %s", err.Error())
		}

		union = &ncasn.RecordUnion{
			Mx: &ncasn.MX{Priority: uint16(priority), Target: fields[5]},
		}
	case "SSHFP":
		recLen := 7
		if len(fields) < recLen {
			return nil, errors.New("missing SSHFP fields")
		}

		var err error

		union, err = parseSshfp(fields[4:])
		if err != nil {
			return nil, err
		}

		if union == nil {
			*skipped++
			data := strings.Join(fields[4:], " ")
			union = &ncasn.RecordUnion{
				Generic: &ncasn.Generic{
					Type:   dns.TypeSSHFP,
					Target: data,
				},
			}
		}
	case "NS":
		union = &ncasn.RecordUnion{
			Ns: &ncasn.NS{
				String: &fields[4],
			},
		}
	case "CNAME":
		union = &ncasn.RecordUnion{
			Cname: &fields[4],
		}
	case "HTTPS":
		union = &ncasn.RecordUnion{
			Generic: &ncasn.Generic{Type: dns.StringToType[typeName], Target: strings.Join(fields[4:], " ")},
		}
	case "SOA", "NSEC3", "NSEC3PARAM", "DNSKEY", "RRSIG", "CDS", "CDNSKEY", "CAA":
		if zone {
			*skipped++

			return nil, nil
		}

		union = &ncasn.RecordUnion{
			Generic: &ncasn.Generic{Type: dns.StringToType[typeName], Target: strings.Join(fields[4:], " ")},
		}
	}

	if union == nil {
		*skipped++

		fmt.Println("unsupported record:", strings.Join(fields, " "))

		return nil, nil
	}

	return &util.GenericNameRecord{Name: subdomain, RecordData: *union}, nil
}

// nolint: cyclop, funlen
func addRecord(record *ncasn.RecordUnion, obj map[string]any) {
	switch {
	case record.A != nil:
		ip, found := obj["ip"]

		var ipCast []string
		if found {
			// Exclusively set below.
			ipCast = ip.([]string) // nolint: forcetypeassert
		}

		obj["ip"] = append(ipCast, net.IP(record.A.Target).String())
	case record.AAAA != nil:
		ip6, found := obj["ip6"]

		var ip6Cast []string
		if found {
			// Ibid.
			ip6Cast = ip6.([]string) // nolint: forcetypeassert
		}

		obj["ip6"] = append(ip6Cast, net.IP(record.AAAA.Bytes).String())
	case record.Srv != nil:
		srv, found := obj["srv"]

		var srvCast [][]any
		if found {
			// Ibid.
			srvCast = srv.([][]any) // nolint: forcetypeassert
		}

		var weight uint16
		if record.Srv.Data.Weight == nil {
			weight = 0
		} else {
			weight = *record.Srv.Data.Weight
		}

		obj["srv"] = append(srvCast, []any{record.Srv.Data.Priority, weight, record.Srv.Data.Port, record.Srv.Data.Target})
	case record.Ds != nil:
		dsToJson(record, obj)
	case record.Txt != nil:
		txt, found := obj["txt"]

		var txtCast [][]string
		if found {
			// Ibid.
			txtCast = txt.([][]string) // nolint: forcetypeassert
		}

		parts := util.SplitTxt(record.Txt.Content)
		obj["txt"] = append(txtCast, parts)
	case record.Tlsa != nil:
		tlsaToJson(record, obj)
	case record.Loc != nil:
		loc, found := obj["loc"]

		var locCast []string
		if found {
			// Ibid.
			locCast = loc.([]string) // nolint: forcetypeassert
		}

		obj["loc"] = append(locCast, record.Loc.String())
	case record.Sshfp != nil:
		sshfp, found := obj["sshfp"]

		var cast [][]any
		if found {
			// Ibid.
			cast = sshfp.([][]any) // nolint: forcetypeassert
		}

		var sha256 uint8 = 2

		obj["sshfp"] = append(cast, []any{
			record.Sshfp.GetKeyAlgo(),
			sha256,
			base64.StdEncoding.EncodeToString(record.Sshfp.Fingerprint),
		})
	case record.Onion != nil:
		tor, found := obj["tor"]

		var cast []string
		if found {
			// Ibid.
			cast = tor.([]string) // nolint: forcetypeassert
		}

		obj["tor"] = append(cast, record.Onion.ToDomain())
	case record.I2p != nil:
		i2p, found := obj["i2p"]

		var cast []string
		if found {
			// Ibid.
			cast = i2p.([]string) // nolint: forcetypeassert
		}

		obj["i2p"] = append(cast, record.I2p.ToDomain())
	case record.I2pLs2 != nil:
		i2p, found := obj["i2p"]

		var cast []string
		if found {
			// Ibid.
			cast = i2p.([]string) // nolint: forcetypeassert
		}

		obj["i2p"] = append(cast, record.I2pLs2.ToDomain())
	case record.Import != nil:
		imports, found := obj["import"]

		var cast [][]string
		if found {
			// Ibid.
			cast = imports.([][]string) // nolint: forcetypeassert
		}

		subArr := []string{record.Import.Name}
		if record.Import.Subdomain != nil {
			subArr = append(subArr, *record.Import.Subdomain)
		}

		obj["import"] = append(cast, subArr)
	case record.Hyphanet != nil:
		obj["freenet"] = record.Hyphanet.ToKey()
	case record.Ns != nil:
		obj["ns"] = *record.Ns
	case record.Cname != nil:
		obj["alias"] = *record.Cname
	case record.Dname != nil:
		obj["translate"] = *record.Dname
	case record.Generic != nil:
		// Unsure if anything in the sample actually reaches this, but it's semantically nice
		generic, found := obj["o"]

		var cast [][]any
		if found {
			// Ibid.
			cast = generic.([][]any) // nolint: forcetypeassert
		}

		b64 := base64.StdEncoding.EncodeToString(wire.ToWire(record))

		obj["o"] = append(cast, []any{record.Generic.Type, b64})
	}
}

func handleSubdomains(obj map[string]any, name string) map[string]any {
	parts := strings.Split(name, ".")
	slices.Reverse(parts)

	last := obj

	for _, part := range parts {
		mapField, found := last["map"]

		var mapCast map[string]any
		if found {
			// Exclusively set below.
			mapCast = mapField.(map[string]any) // nolint: forcetypeassert
		} else {
			mapCast = map[string]any{}
			last["map"] = mapCast
		}

		subField, found := mapCast[part]

		var sub map[string]any
		if found {
			// Ibid.
			sub = subField.(map[string]any) // nolint: forcetypeassert
		} else {
			sub = map[string]any{}
			mapCast[part] = sub
		}

		last = sub
	}

	return last
}

func objToZone(obj map[string]any, base string, records []util.GenericNameRecord, hidden bool) (*util.Zone, error) {
	str, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}

	ret := util.Zone{Json: string(str), Base: base}

	slices.SortFunc(records, util.CmpRecords)

	ret.Cbor, err = cbor.RecordsToCbor(records, hidden)
	if err != nil {
		return nil, err
	}

	ret.Tor, err = tor.RecordsToTor(records, hidden)
	if err != nil {
		return nil, fmt.Errorf("failed to convert zone records to Tor format: %s", err.Error())
	}

	ret.Zone = &util.GenericZone{Records: util.CollapseNsGlues(records, base)}

	return &ret, nil
}

func zoneFromRecords(records []util.GenericNameRecord, base string, hidden bool) (*util.Zone, error) {
	obj := map[string]any{}

	for _, record := range records {
		switch {
		case hidden:
			record.Name = "0"
		case record.RecordData.Txt != nil && record.RecordData.Txt.DnsWl:
			if len(record.Name) == 0 {
				record.Name = "_token._dnswl"
			} else {
				record.Name = "_token._dnswl." + record.Name
			}
		case record.RecordData.Srv != nil && record.RecordData.Srv.Meta != nil:
			prefix := record.RecordData.Srv.Meta.ToPrefix()
			if len(record.Name) == 0 {
				record.Name = prefix
			} else {
				record.Name = prefix + "." + record.Name
			}
		case len(record.Name) == 0:
			addRecord(&record.RecordData, obj)

			continue
		}

		subObj := handleSubdomains(obj, record.Name)

		addRecord(&record.RecordData, subObj)
	}

	return objToZone(obj, base, records, hidden)
}

func readZone(filePath string, hidden bool) (*util.Zone, error) {
	// Passing untrusted arguments to a benchmark would be problematic anyway.
	fd, err := os.Open(filePath) // nolint: gosec
	if err != nil {
		return nil, err
	}

	// Handling Close() failures is surely out of scope?
	defer fd.Close() // nolint: errcheck

	var records []util.GenericNameRecord

	// Primarily used to handle RFC 3597
	parser := dns.NewZoneParser(fd, "", filePath)
	record, ok := parser.Next()
	n := 0
	skipped := 0

	for ok {
		raw := record.String()

		parsed, err := ParseRecord(raw, true, &skipped)
		if err != nil {
			return nil, err
		}

		if parsed != nil {
			records = append(records, *parsed)
		}

		n++
		record, ok = parser.Next()
	}

	err = parser.Err()
	if err != nil {
		return nil, err
	}

	segments := strings.Split(filePath, "/")
	base := strings.TrimSuffix(segments[len(segments)-1], ".zone")

	ret, err := zoneFromRecords(records, base, hidden)
	if err != nil {
		return nil, err
	}

	ret.Coverage = float64(n-skipped) / float64(n)

	return ret, nil
}

func ReadZones(dir string, hidden bool) ([]util.Zone, error) {
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

		zone, err := readZone(dir+"/"+name, hidden)
		if err != nil {
			return nil, err
		}

		ret = append(ret, *zone)
	}

	return ret, nil
}

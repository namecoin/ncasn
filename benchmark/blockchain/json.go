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
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
	"slices"
	"strings"

	"github.com/miekg/dns"
	"github.com/sofia-nep/ncasn"
	"github.com/sofia-nep/ncasn/benchmark/cbor"
	"github.com/sofia-nep/ncasn/benchmark/tor"
	"github.com/sofia-nep/ncasn/benchmark/util"
	"github.com/sofia-nep/ncasn/benchmark/zone"
)

func parseTypeOrSlice[E any](value any) ([]E, error) {
	typeOf := reflect.TypeOf(value)
	if typeOf == nil {
		return nil, errors.New("Nil value")
	}

	expectedType := reflect.TypeFor[E]()

	switch typeOf {
	case expectedType:
		return []E{value.(E)}, nil
	case reflect.SliceOf(expectedType):
		return value.([]E), nil
	default:
		if typeOf.Kind() != reflect.Slice || typeOf.Elem().Kind() != reflect.Interface {
			return nil, fmt.Errorf("Unexpected type %s != %s", typeOf.String(), expectedType.String())
		}

		// Handle encoding/json decoding things too generically as []any
		var ret []E
		for _, elem := range value.([]any) {
			cast, ok := elem.(E)
			if !ok {
				return nil, errors.New("Invalid element type")
			}

			ret = append(ret, cast)
		}

		return ret, nil
	}
}

func handleField(key string, value any, name string) ([]ncasn.Record, error) {
	var ret []ncasn.Record
	switch key {
	case "map":
		cast, ok := value.(map[string]any)
		if !ok {
			return nil, errors.New("Non-object map value")
		}

		for kMap, vMap := range cast {
			typeOf := reflect.TypeOf(vMap)
			if typeOf == nil {
				fmt.Println("Nil value")
				continue
			}

			kind := typeOf.Kind()
			switch kind {
			case reflect.String:
				str := vMap.(string)
				ip := net.ParseIP(str)
				if ip == nil {
					fmt.Println("Invalid subdomain IP address:", str)
					continue
				}
				ip = ip.To4()

				if ip == nil {
					fmt.Println("IPv6 but should be IPv4")
					continue
				}

				union := ncasn.RecordUnion{A: &ncasn.A{Target: ip}}

				ret = append(ret, ncasn.Record{
					Name:       &kMap,
					RecordData: union,
				})
			case reflect.Map:
				for kNested, vNested := range vMap.(map[string]any) {
					var relName string
					if len(name) == 0 {
						relName = kMap
					} else {
						relName = kMap + "." + name
					}
					nested, err := handleField(kNested, vNested, relName)
					if err == nil {
						ret = append(ret, nested...)
					} else {
						fmt.Println("Failed to parse subdomain:", err.Error())
					}
				}
			default:
				fmt.Println("Invalid subdomain type:", kind.String())
			}
		}
	case "import":
		withSub, ok := value.([]any)
		if ok {
			leave := true
			for _, elemAny := range withSub {
				elem, ok := elemAny.([]any)
				if !ok {
					leave = false
					break
				}

				if len(elem) == 0 {
					continue
				}

				base, ok := elem[0].(string)
				if !ok || len(base) < 3 || len(base) > 63 {
					continue
				}

				var subPtr *string
				if len(elem) >= 2 {
					sub, ok := elem[1].(string)
					if !ok {
						continue
					}
					subPtr = &sub
				}

				ret = append(ret, ncasn.Record{
					Name: &name,
					RecordData: ncasn.RecordUnion{
						Import: &ncasn.Import{
							Name:      base,
							Subdomain: subPtr,
						},
					},
				})
			}

			if leave {
				break
			}
		}

		disamb, err := parseTypeOrSlice[string](value)
		if err != nil {
			return nil, fmt.Errorf("Failed to parse import: %s", err.Error())
		}

		for _, elem := range disamb {
			if len(elem) < 3 || len(elem) > 63 {
				continue
			}
			ret = append(ret, ncasn.Record{
				Name: &name,
				RecordData: ncasn.RecordUnion{
					Import: &ncasn.Import{
						Name: elem,
					},
				},
			})
		}
	case "ip":
		disamb, err := parseTypeOrSlice[string](value)
		if err != nil {
			return nil, fmt.Errorf("Failed to parse ip: %s", err.Error())
		}

		for _, elem := range disamb {
			ip := net.ParseIP(elem)
			if ip == nil {
				return nil, fmt.Errorf("Failed to parse ip: %s", elem)
			}
			ip = ip.To4()

			if ip == nil {
				return nil, errors.New("IPv6 but should be IPv4")
			}

			ret = append(ret, ncasn.Record{
				Name:       &name,
				RecordData: ncasn.RecordUnion{A: &ncasn.A{Target: ip}},
			})
		}
	case "ip6":
		disamb, err := parseTypeOrSlice[string](value)
		if err != nil {
			return nil, fmt.Errorf("Failed to parse ip6: %s", err.Error())
		}

		for _, elem := range disamb {
			ip := net.ParseIP(elem)
			if ip == nil {
				return nil, fmt.Errorf("Failed to parse ip6: %s", elem)
			}

			if strings.Contains(elem, ".") {
				return nil, errors.New("IPv4 but should be IPv6")
			}

			ret = append(ret, ncasn.Record{
				Name:       &name,
				RecordData: ncasn.RecordUnion{AAAA: &ncasn.AAAA{Bytes: ip}},
			})
		}
	case "alias":
		typeOf := reflect.TypeOf(value)
		if typeOf == nil {
			return nil, errors.New("Nil value")
		}

		kind := typeOf.Kind()
		if kind != reflect.String {
			return nil, fmt.Errorf("Invalid kind when parsing alias: %s", kind.String())
		}

		str := value.(string)
		if len(str) > 255 || !util.IsAscii(str) {
			break
		}

		ret = append(ret, ncasn.Record{
			Name: &name,
			RecordData: ncasn.RecordUnion{Generic: &ncasn.Generic{
				Type:   dns.TypeCNAME,
				Target: str,
			}},
		})
	case "srv":
		parsed, err := parseSrv(&name, value)
		if err != nil {
			return nil, err
		}

		ret = append(ret, parsed...)
	case "ds":
		parsed, err := parseDs(&name, value)
		if err != nil {
			return nil, err
		}

		ret = append(ret, parsed...)
	case "txt":
		if name == "_dnslink" {
			str, ok := value.(string)
			if !ok {
				return nil, errors.New("dnslink TXT record is not a string")
			}

			cut, ok := strings.CutPrefix(str, "dnslink=")
			if !ok {
				return nil, fmt.Errorf("Invalid dnslink TXT record: %s", str)
			}

			if !strings.HasPrefix(cut, "/ipns/") {
				return nil, fmt.Errorf("Non-IPNS dnslink TXT record: %s", cut)
			}

			ipns, err := ncasn.IpnsToRecord(cut)
			if err != nil {
				return nil, fmt.Errorf("Invalid IPNS TXT record: %s", err.Error())
			}

			ret = append(ret, ncasn.Record{
				Name: &name,
				RecordData: ncasn.RecordUnion{
					Ipns: ipns,
				},
			})
		} else {
			parsed, err := parseTxt(&name, value)
			if err != nil {
				return nil, fmt.Errorf("Failed to parse TXT record: %s", err.Error())
			}

			ret = append(ret, parsed...)
		}
	case "tls":
		arr, ok := value.([][]any)
		if !ok {
			return nil, errors.New("tls field is not an array of arrays")
		}

		for _, elem := range arr {
			parsed, err := parseTlsaRecord(&name, elem)
			if err != nil {
				fmt.Println("Failed to parse TLSA record:", err.Error())
				continue
			}

			if parsed != nil {
				ret = append(ret, *parsed)
			}
		}
	case "loc":
		records, err := parseTypeOrSlice[string](value)
		if err != nil {
			return nil, fmt.Errorf("Invalid LOC type: %s", err.Error())
		}

		for _, record := range records {
			parsed, err := parseLocRecord(&name, record)
			if err != nil {
				fmt.Println("Failed to parse LOC record:", err.Error())
				continue
			}

			ret = append(ret, *parsed)
		}
	case "sshfp":
		records, ok := value.([][]any)
		if !ok {
			return nil, errors.New("sshfp field is not a slice of slices")
		}

		for _, record := range records {
			length := len(record)
			if length < 3 {
				fmt.Println("SSHFP record too short")
				continue
			}

			algo, err := parseUint8(record[0])
			if err != nil {
				fmt.Println("Invalid SSHFP algorithm:", err.Error())
				continue
			}

			if *algo < 4 {
				fmt.Println("Unsupported SSHFP algorithm:", *algo)
				continue
			}

			*algo -= 4

			digestType, err := parseUint8(record[1])
			if err != nil {
				fmt.Println("Invalid digest algorithm:", err.Error())
				continue
			}

			if *digestType != 2 {
				fmt.Println("Non-SHA-256 SSHFP digest algorithm:", *digestType)
				continue
			}

			digest, ok := record[2].(string)
			if !ok {
				fmt.Println("SSHFP digest is not a string")
				continue
			}

			bytes, err := base64.StdEncoding.DecodeString(digest)
			if err != nil {
				fmt.Println("Invalid SSHFP digest:", err.Error())
				continue
			}

			length = len(bytes)
			if length != 32 {
				fmt.Println("Invalid SSHFP SHA-256 length:", length)
				continue
			}

			ret = append(ret, ncasn.Record{
				Name: &name,
				RecordData: ncasn.RecordUnion{
					Sshfp: &ncasn.SSHFP{
						KeyAlgoIndex: *algo,
						Fingerprint:  bytes,
					},
				},
			})
		}
	case "tor":
		records, err := parseTypeOrSlice[string](value)
		if err != nil {
			return nil, fmt.Errorf("Invalid tor record type: %s", err.Error())
		}

		for _, record := range records {
			parsed, err := ncasn.OnionRecordFromDomain(record)
			if err != nil {
				fmt.Println("Invalid onion domain:", err.Error())
				continue
			}

			ret = append(ret, ncasn.Record{
				Name: &name,
				RecordData: ncasn.RecordUnion{
					Onion: parsed,
				},
			})
		}
	case "i2p":
		records, err := parseTypeOrSlice[string](value)
		if err != nil {
			return nil, fmt.Errorf("Invalid i2p record type: %s", err.Error())
		}

		for _, record := range records {
			old, ls2, err := ncasn.I2pRecordFromDomain(record)
			if err != nil {
				fmt.Println("Invalid i2p domain:", err.Error())
				continue
			}

			ret = append(ret, ncasn.Record{
				Name: &name,
				RecordData: ncasn.RecordUnion{
					I2p:    old,
					I2pLs2: ls2,
				},
			})
		}
	case "freenet":
		str, ok := value.(string)
		if !ok {
			return nil, errors.New("freenet field is not a string")
		}

		parsed, err := ncasn.USKRecordFromKey(str)
		if err != nil {
			return nil, fmt.Errorf("Invalid USK: %s", err.Error())
		}

		ret = append(ret, ncasn.Record{
			Name: &name,
			RecordData: ncasn.RecordUnion{
				Hyphanet: parsed,
			},
		})
	case "translate":
		str, ok := value.(string)
		if !ok {
			return nil, errors.New("translate field is not a string")
		}

		if len(str) > 255 || !util.IsAscii(str) {
			break
		}

		ret = append(ret, ncasn.Record{
			Name: &name,
			RecordData: ncasn.RecordUnion{
				Generic: &ncasn.Generic{
					Type:   dns.TypeDNAME,
					Target: str,
				},
			},
		})
	case "ns", "dns":
		records, err := parseTypeOrSlice[string](value)
		if err != nil {
			return nil, fmt.Errorf("Invalid ns/dns record type: %s", err.Error())
		}

		for _, record := range records {
			if len(record) > 255 || !util.IsAscii(record) {
				continue
			}
			ret = append(ret, ncasn.Record{
				Name: &name,
				RecordData: ncasn.RecordUnion{
					Generic: &ncasn.Generic{
						Type:   dns.TypeNS,
						Target: record,
					},
				},
			})
		}
	case "o":
		arr, ok := value.([][]any)
		if !ok {
			return nil, errors.New("Invalid o field")
		}

		for _, record := range arr {
			if len(record) < 2 {
				fmt.Println("Arbitrary record is too short")
				continue
			}

			typeId, err := parseUint16(record[0])
			if err != nil {
				fmt.Println("Invalid record type:", err.Error())
				continue
			}

			prohib := []uint16{
				dns.TypeNS,
				dns.TypeCNAME,
				dns.TypeSOA,
				dns.TypeDNAME,
				dns.TypeDS,
				dns.TypeRRSIG,
				dns.TypeNSEC,
				dns.TypeNSEC3,
			}
			if slices.Contains(prohib, *typeId) {
				fmt.Println("Unsupported arbitrary record type:", *typeId)
				continue
			}

			data, ok := record[1].(string)
			if !ok {
				fmt.Println("Invalid arbitrary record data type")
				continue
			}

			bytes, err := base64.StdEncoding.DecodeString(data)
			if err != nil {
				fmt.Println("Invalid arbitrary record base64:", err.Error())
				continue
			}

			header := dns.RR_Header{
				Name:     name,
				Rrtype:   *typeId,
				Class:    dns.ClassINET,
				Rdlength: uint16(len(bytes)),
			}

			parsed, _, err := dns.UnpackRRWithHeader(header, bytes, 0)
			if err != nil {
				fmt.Println("Invalid arbitrary record:", err.Error())
				continue
			}

			decoded, err := zone.ParseRecord(parsed.String(), false)
			if err != nil {
				fmt.Println("Invalid arbitrary record:", err.Error())
				continue
			}

			if decoded != nil {
				ret = append(ret, *decoded)
			}
		}
	}

	return ret, nil
}

func parseWhois(value any) *ncasn.Whois {
	typeOf := reflect.TypeOf(value)
	if typeOf == nil {
		fmt.Println("Nil value")
		return nil
	}

	kind := typeOf.Kind()
	var whois *ncasn.Whois
	switch kind {
	case reflect.Map:
		cast, ok := value.(map[string]any)
		if !ok {
			fmt.Println("Invalid info field type:", typeOf.String())
			return nil
		}

		var fields ncasn.WhoisFields

		r, ok := cast["r"]
		if ok {
			rStr, ok := r.(string)
			if !ok {
				fmt.Println("Invalid registrant type")
				return nil
			}
			fields.Registrant = &rStr
		}

		rr, ok := cast["rr"]
		if ok {
			rrStr, ok := rr.(string)
			if !ok {
				fmt.Println("Invalid registrar type")
				return nil
			}
			fields.Registrar = &rrStr
		}

		a, ok := cast["a"]
		if ok {
			aStr, ok := a.(string)
			if !ok {
				fmt.Println("Invalid admin type")
				return nil
			}
			fields.AdmContact = &aStr
		}

		t, ok := cast["t"]
		if ok {
			tStr, ok := t.(string)
			if !ok {
				fmt.Println("Invalid tech type")
				return nil
			}
			fields.TechContact = &tStr
		}

		whois = &ncasn.Whois{Fields: &fields}
	case reflect.String:
		cast := value.(string)
		whois = &ncasn.Whois{Entity: &cast}
	default:
		fmt.Println("Invalid info field type:", typeOf.String())
	}

	return whois
}

func jsonToUper(data *Name) (*ncasn.Zone, error) {
	parser := json.NewDecoder(bytes.NewReader([]byte(data.Value)))
	parser.UseNumber()

	var parsed map[string]any
	err := parser.Decode(&parsed)
	if err != nil {
		return nil, err
	}

	var ret []ncasn.Record
	var zone ncasn.Zone
	for key, value := range parsed {
		if key == "info" {
			zone.Info = parseWhois(value)
			continue
		}

		record, err := handleField(key, value, "")
		if err != nil {
			fmt.Printf("Error while parsing %s for %s: %s\n", key, data.Name, err.Error())
			continue
		}

		ret = append(ret, record...)
	}

	if ret == nil {
		return nil, nil
	}

	ret = applySuppression(ret)

	zone.Records = ret
	return &zone, nil
}

func combine(zone *ncasn.Zone, json *Name) (*util.Zone, error) {
	slices.SortFunc(zone.Records, util.CmpRecords)
	cborEncoded, err := cbor.RecordsToCbor(zone.Records)
	if err != nil {
		return nil, err
	}

	torEncoded, err := tor.RecordsToTor(zone.Records)
	if err != nil {
		return nil, fmt.Errorf("Failed to convert blockchain records to Tor format: %s", err.Error())
	}

	return &util.Zone{Zone: zone, Json: json.Value, Cbor: cborEncoded, Tor: torEncoded}, nil
}

func JsonFileToUper(file string) ([]util.Zone, error) {
	fd, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer fd.Close()

	data, err := io.ReadAll(fd)
	if err != nil {
		return nil, err
	}

	var parsed []Name
	err = json.Unmarshal(data, &parsed)
	if err != nil {
		return nil, err
	}

	var ret []util.Zone
	for _, name := range parsed {
		// Impossible JSON
		if !strings.HasPrefix(name.Value, "{") {
			continue
		}

		zone, err := jsonToUper(&name)
		if err != nil {
			fmt.Printf("Failed to parse %s = %s: %s\n", name.Name, name.Value, err.Error())
			continue
		}

		if zone != nil {
			merged, err := combine(zone, &name)
			if err != nil {
				return nil, err
			}

			ret = append(ret, *merged)
		}
	}

	return ret, nil
}

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
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"slices"
	"strconv"
	"strings"

	"github.com/miekg/dns"
	"github.com/namecoin/go-asn/mixedradix"
	"github.com/namecoin/ncasn"
	"github.com/namecoin/ncasn/benchmark/util"
)

func parseSrvData(elem []any) (*ncasn.SRVData, error) {
	priority, err := parseUint16(elem[0])
	if err != nil {
		return nil, fmt.Errorf("srv priority is not a uint16: %w", err)
	}

	weight, err := parseUint16(elem[1])
	if err != nil {
		return nil, fmt.Errorf("srv weight is not a uint16: %w", err)
	}

	if *weight == 0 {
		weight = nil
	}

	port, err := parseUint16(elem[2])
	if err != nil {
		return nil, fmt.Errorf("srv port is not a uint16: %w", err)
	}

	target, ok := elem[3].(string)
	if !ok {
		return nil, errors.New("srv target is not a string")
	}

	return &ncasn.SRVData{
		Priority: *priority,
		Weight:   weight,
		Port:     *port,
		Target:   target,
	}, nil
}

func parseSrv(name string, elem []any) (*util.GenericNameRecord, error) {
	data, err := parseSrvData(elem)
	if err != nil {
		return nil, err
	}

	if len(data.Target) > 255 || !mixedradix.IsValidDnsName(data.Target) {
		return nil, nil
	}

	var smtpPort uint16 = 25
	if data.Port == smtpPort {
		name, found := strings.CutPrefix(name, "_smtp._tcp")
		if found {
			name = strings.TrimPrefix(name, ".")

			return &util.GenericNameRecord{
				Name: name,
				RecordData: ncasn.RecordUnion{
					Mx: &ncasn.MX{
						Target:   data.Target,
						Priority: data.Priority,
					},
				},
			}, nil
		}
	}

	meta := ncasn.SrvNameToMeta(name)
	if meta != nil {
		labels := strings.Split(name, ".")

		baseParts := 2
		if len(labels) == baseParts {
			name = ""
		} else {
			name = strings.Join(labels[2:], ".")
		}
	}

	return &util.GenericNameRecord{
		Name: name,
		RecordData: ncasn.RecordUnion{
			Srv: &ncasn.SRV{
				Meta: meta,
				Data: *data,
			},
		},
	}, nil
}

func parseSrvs(name string, value any) ([]util.GenericNameRecord, error) {
	if value == nil {
		return nil, errors.New("nil value")
	}

	list, ok := value.([]any)
	if !ok {
		return nil, errors.New("srv is not a slice")
	}

	var ret []util.GenericNameRecord

	for _, elemAny := range list {
		elem, ok := elemAny.([]any)
		if !ok {
			return nil, errors.New("srv element type is not slice")
		}

		validLen := 4
		if len(elem) < validLen {
			return nil, errors.New("srv array with < 4 parts")
		}

		parsed, err := parseSrv(name, elem)
		if err != nil {
			return nil, err
		}

		if parsed == nil {
			continue
		}

		ret = append(ret, *parsed)
	}

	return ret, nil
}

func spdf(service *string, protocol *string) string {
	var ret string

	if service != nil && *service == "" {
		service = nil
	}

	if protocol != nil && *protocol == "" {
		protocol = nil
	}

	if service != nil {
		if *service == "*" {
			ret += "*."
		} else {
			ret += "_" + *service + "."
		}
	}

	if protocol != nil {
		if *protocol == "*" {
			ret += "*."
		} else {
			ret += "_" + *protocol + "."
		}
	}

	return ret
}

func parseSingleGenericDs(elemAny any) (*ncasn.Generic, error) {
	elem, ok := elemAny.([]any)
	if !ok {
		return nil, errors.New("ds element type is not slice")
	}

	minValid := 4
	if len(elem) < minValid {
		return nil, errors.New("ds array with < 4 parts")
	}

	var str string

	key, err := parseUint16(elem[0])
	if err != nil {
		return nil, fmt.Errorf("ds key is not a uint16: %s", err.Error())
	}

	str += strconv.Itoa(int(*key)) + " "

	algo, err := parseUint8(elem[1])
	if err != nil {
		return nil, fmt.Errorf("ds key algorithm is not a uint8: %s", err.Error())
	}

	str += strconv.Itoa(int(*algo)) + " "

	digestType, err := parseUint8(elem[2])
	if err != nil {
		return nil, fmt.Errorf("ds digest type is not a uint8: %s", err.Error())
	}

	str += strconv.Itoa(int(*digestType)) + " "

	digest, ok := elem[3].(string)
	if !ok {
		return nil, errors.New("ds digest is not a string")
	}

	data, err := base64.StdEncoding.DecodeString(digest)
	if err != nil {
		return nil, err
	}

	digest = hex.EncodeToString(data)

	str += digest

	return &ncasn.Generic{
		Type:   dns.TypeDS,
		Target: str,
	}, nil
}

func parseGenericDs(name string, value any) ([]util.GenericNameRecord, error) {
	typeOf := reflect.TypeOf(value)
	if typeOf == nil {
		return nil, errors.New("nil value")
	}

	kind := typeOf.Kind()
	if kind != reflect.Slice {
		return nil, errors.New("ds is not a slice")
	}

	// Checked above.
	list := value.([]any) // nolint: forcetypeassert
	ret := []util.GenericNameRecord{}

	for _, elemAny := range list {
		rec, err := parseSingleGenericDs(elemAny)
		if err != nil {
			return nil, err
		}

		ret = append(ret, util.GenericNameRecord{
			Name: name,
			RecordData: ncasn.RecordUnion{
				Generic: rec,
			},
		})
	}

	return ret, nil
}

func parseSingleService(name string, record []any) (*util.GenericNameRecord, error) {
	length := len(record)

	validLen := 6
	if length < validLen {
		return nil, fmt.Errorf("too few service record elements: %d", length)
	}

	service := record[0]

	var serviceStr *string

	if service != nil {
		cast, ok := service.(string)
		if ok {
			serviceStr = &cast
		} else {
			serviceInt, err := parseUint16(service)
			if err != nil {
				return nil, err
			}

			tmp := strconv.Itoa(int(*serviceInt))
			serviceStr = &tmp
		}
	}

	protocol := record[1]

	var protocolStr *string

	if protocol != nil {
		cast, ok := protocol.(string)
		if ok {
			protocolStr = &cast
		} else {
			protocolInt, err := parseUint16(protocol)
			if err != nil {
				return nil, err
			}

			tmp := strconv.Itoa(int(*protocolInt))
			protocolStr = &tmp
		}
	}

	thisName := name

	prefix := spdf(serviceStr, protocolStr)
	if len(thisName) == 0 {
		thisName = strings.TrimSuffix(prefix, ".")
	} else {
		thisName = prefix + thisName
	}

	return parseSrv(thisName, record[2:])
}

func parseService(name string, value any) ([]util.GenericNameRecord, error) {
	if value == nil {
		return nil, errors.New("nil value")
	}

	list, ok := value.([]any)
	if !ok {
		return nil, errors.New("service array is not a slice")
	}

	ret := []util.GenericNameRecord{}

	for _, srv := range list {
		record, ok := srv.([]any)
		if !ok {
			return nil, errors.New("service is not a slice")
		}

		parsed, err := parseSingleService(name, record)
		if err != nil {
			return nil, err
		}

		if parsed != nil {
			ret = append(ret, *parsed)
		}
	}

	return ret, nil
}

func parseSingleDs(elem []any, skipped *int) (*ncasn.DS, error) {
	validLen := 4
	if len(elem) < validLen {
		return nil, errors.New("ds array with < 4 parts")
	}

	key, err := parseUint16(elem[0])
	if err != nil {
		return nil, fmt.Errorf("ds key is not a uint16: %s", err.Error())
	}

	algo, err := parseUint8(elem[1])
	if err != nil {
		return nil, fmt.Errorf("ds key algorithm is not a uint8: %s", err.Error())
	}

	if !slices.Contains(ncasn.DS_KEY_ALGOS, *algo) {
		*skipped++

		fmt.Println("unsupported ds key algorithm:", *algo)

		return nil, nil
	}

	digestType, err := parseUint8(elem[2])
	if err != nil {
		return nil, fmt.Errorf("ds digest type is not a uint8: %s", err.Error())
	}

	if !slices.Contains(ncasn.DS_DIGEST_TYPES, *digestType) {
		*skipped++

		fmt.Println("unsupported ds digest type:", *digestType)

		return nil, nil
	}

	digest, ok := elem[3].(string)
	if !ok {
		return nil, errors.New("ds digest is not a string")
	}

	bytes, err := base64.StdEncoding.DecodeString(digest)
	if err != nil {
		return nil, err
	}

	union, err := util.ParseDsDigest(*digestType, bytes)
	if err != nil {
		return nil, err
	}

	return &ncasn.DS{
		KeyTag: *key,
		// Known to be valid if it reaches here.
		AlgorithmIndex: uint8(ncasn.GetKeyAlgorithmIndex(*algo)), // nolint: gosec
		Digest:         *union,
	}, nil
}

func parseDs(name string, value any, skipped *int) ([]util.GenericNameRecord, error) {
	if value == nil {
		return nil, errors.New("nil value")
	}

	list, ok := value.([]any)
	if !ok {
		return nil, errors.New("ds is not a slice")
	}

	var ret []util.GenericNameRecord

	for _, elemAny := range list {
		elem, ok := elemAny.([]any)
		if !ok {
			return nil, errors.New("ds element type is not slice")
		}

		record, err := parseSingleDs(elem, skipped)
		if err != nil {
			return nil, err
		}

		if record != nil {
			ret = append(ret, util.GenericNameRecord{
				Name: name,
				RecordData: ncasn.RecordUnion{
					Ds: record,
				},
			})
		}
	}

	return ret, nil
}

func parseTxtString(value string) (*string, error) {
	var list []string

	for len(value) > 255 {
		list = append(list, "\""+value[0:255]+"\"")
		value = value[255:]
	}

	if len(value) > 0 {
		list = append(list, "\""+value+"\"")
	}

	ret := strings.Join(list, " ")

	length := len(ret)

	maxLen := 4096
	if length > maxLen {
		return nil, fmt.Errorf("TXT length %d > 4096", length)
	}

	if !util.IsAscii(ret) {
		return nil, errors.New("TXT data is not ASCII")
	}

	return &ret, nil
}

func parseTxtParts(nested []any) (*string, error) {
	var str string

	for _, item := range nested {
		itemStr, ok := item.(string)
		if !ok {
			return nil, errors.New("non-string TXT part")
		}

		length := len(itemStr)

		maxLen := 255
		if length > maxLen {
			return nil, fmt.Errorf("TXT part length %d > 255", length)
		}

		str += "\"" + itemStr + "\"" + " "
		length = len(str)
		// + 1 due to the trailing space
		maxLen = 4097

		if length > maxLen {
			return nil, errors.New("TXT record too large")
		}
	}

	str = str[:len(str)-1]

	return &str, nil
}

// nolint: funlen
func parseTxt(name string, value any) ([]util.GenericNameRecord, error) {
	if value == nil {
		return nil, errors.New("nil value")
	}

	str, ok := value.(string)
	if ok {
		parsed, err := parseTxtString(str)
		if err != nil {
			return nil, err
		}

		return []util.GenericNameRecord{{
			Name: name,
			RecordData: ncasn.RecordUnion{
				Txt: &ncasn.TXT{
					Content: *parsed,
				},
			},
		}}, nil
	}

	slice, ok := value.([]any)
	if !ok {
		return nil, errors.New("invalid TXT record type")
	}

	ret := []util.GenericNameRecord{}

	for _, elem := range slice {
		str, ok = elem.(string)
		if ok {
			parsed, err := parseTxtString(str)
			if err != nil {
				return nil, err
			}

			ret = append(ret, util.GenericNameRecord{
				Name: name,
				RecordData: ncasn.RecordUnion{
					Txt: &ncasn.TXT{
						Content: *parsed,
					},
				},
			})

			continue
		}

		nested, ok := elem.([]any)
		if !ok {
			return nil, errors.New("invalid TXT element type")
		}

		strPtr, err := parseTxtParts(nested)
		if err != nil {
			return nil, err
		}

		ret = append(ret, util.GenericNameRecord{
			Name: name,
			RecordData: ncasn.RecordUnion{
				Txt: &ncasn.TXT{
					Content: *strPtr,
				},
			},
		})
	}

	return ret, nil
}

func parseUint8(value any) (*uint8, error) {
	num, ok := value.(json.Number)
	if !ok {
		return nil, errors.New("value not a number")
	}

	integer, err := num.Int64()
	if err != nil {
		return nil, fmt.Errorf("value not an integer: %s", err.Error())
	}

	if integer < 0 || integer > math.MaxUint8 {
		return nil, fmt.Errorf("%d cannot be represented as a uint8", integer)
	}

	cast := uint8(integer)

	return &cast, nil
}

func parseUint16(value any) (*uint16, error) {
	num, ok := value.(json.Number)
	if !ok {
		return nil, errors.New("value not a number")
	}

	integer, err := num.Int64()
	if err != nil {
		return nil, fmt.Errorf("value not an integer: %s", err.Error())
	}

	if integer < 0 || integer > math.MaxUint16 {
		return nil, fmt.Errorf("%d cannot be represented as a uint16", integer)
	}

	cast := uint16(integer)

	return &cast, nil
}

func parseGenericTlsa(name string, value []any) (*util.GenericNameRecord, error) {
	length := len(value)

	validLen := 4
	if length < validLen {
		return nil, errors.New("too few values for a TLSA record")
	}

	var record string

	usage, err := parseUint8(value[0])
	if err != nil {
		return nil, fmt.Errorf("TLSA certificate usage is not a uint8: %s", err.Error())
	}

	record += strconv.Itoa(int(*usage)) + " "

	selector, err := parseUint8(value[1])
	if err != nil {
		return nil, fmt.Errorf("TLSA selector is not a uint8: %s", err.Error())
	}

	record += strconv.Itoa(int(*selector)) + " "

	matchingType, err := parseUint8(value[2])
	if err != nil {
		return nil, fmt.Errorf("TLSA matching type is not a uint8: %s", err.Error())
	}

	record += strconv.Itoa(int(*matchingType)) + " "

	dataStr, ok := value[3].(string)
	if !ok {
		return nil, errors.New("TLSA data is not a string")
	}

	data, err := base64.StdEncoding.DecodeString(dataStr)
	if err != nil {
		return nil, err
	}

	dataStr = hex.EncodeToString(data)

	record += dataStr

	return &util.GenericNameRecord{Name: name, RecordData: ncasn.RecordUnion{Generic: &ncasn.Generic{
		Type:   dns.TypeTLSA,
		Target: record,
	}}}, nil
}

func parseTlsaDigest(matchingType uint8, data []byte, skipped *int) (*ncasn.TlsaUnion, error) {
	length := len(data)

	var union ncasn.TlsaUnion

	var (
		sha256Id   uint8 = 1
		sha512Id   uint8 = 2
		unassigned uint8 = 3
	)

	switch matchingType {
	case sha256Id:
		if length != sha256.Size {
			return nil, fmt.Errorf("SHA-256 TLSA length %d != 32", length)
		}

		union = ncasn.TlsaUnion{
			Sha256: &data,
		}
	case sha512Id:
		if length != sha512.Size {
			return nil, fmt.Errorf("SHA-512 TLSA length %d != 64", length)
		}

		union = ncasn.TlsaUnion{
			Sha512: &data,
		}
	case unassigned:
		if length < 32 || length > 64 {
			return nil, fmt.Errorf("unsupported TLSA data length: %d", length)
		}

		union = ncasn.TlsaUnion{
			Unassigned0: &data,
		}
	default:
		*skipped++

		return nil, fmt.Errorf("unsupported TLSA matching type: %d", matchingType)
	}

	return &union, nil
}

func parseTlsaRecord(name string, value []any, skipped *int) (*util.GenericNameRecord, error) {
	length := len(value)

	validLen := 4
	if length < validLen {
		return nil, errors.New("too few values for a TLSA record")
	}

	usage, err := parseUint8(value[0])
	if err != nil {
		return nil, fmt.Errorf("TLSA certificate usage is not a uint8: %s", err.Error())
	}

	var daneTa uint8 = 2
	if *usage != daneTa {
		*skipped++

		return nil, fmt.Errorf("unsupported TLSA certificate usage: %d", *usage)
	}

	selector, err := parseUint8(value[1])
	if err != nil {
		return nil, fmt.Errorf("TLSA selector is not a uint8: %s", err.Error())
	}

	if *selector > 1 {
		*skipped++

		return nil, fmt.Errorf("unsupported TLSA selector: %d", *selector)
	}

	matchingType, err := parseUint8(value[2])
	if err != nil {
		return nil, fmt.Errorf("TLSA matching type is not a uint8: %s", err.Error())
	}

	dataStr, ok := value[3].(string)
	if !ok {
		return nil, errors.New("TLSA data is not a string")
	}

	data, err := base64.StdEncoding.DecodeString(dataStr)
	if err != nil {
		return nil, fmt.Errorf("TLSA data is not base64: %s", err.Error())
	}

	union, err := parseTlsaDigest(*matchingType, data, skipped)
	if err != nil {
		return nil, err
	}

	return &util.GenericNameRecord{
		Name: name,
		RecordData: ncasn.RecordUnion{Tlsa: &ncasn.TLSA{
			Selector:        *selector,
			AssociationData: *union,
		}},
	}, nil
}

func parseLocRecord(name string, value string) (*util.GenericNameRecord, error) {
	data, err := ncasn.StringToLoc(value)
	if err != nil {
		return nil, err
	}

	return &util.GenericNameRecord{Name: name, RecordData: ncasn.RecordUnion{Loc: data}}, nil
}

func parseGenericSshfp(name string, value any) (*util.GenericNameRecord, error) {
	record, ok := value.([]any)
	if !ok {
		return nil, errors.New("sshfp field is not a slice of slices")
	}

	minLen := 3

	length := len(record)
	if length < minLen {
		return nil, errors.New("SSHFP record too short")
	}

	algo, err := parseUint8(record[0])
	if err != nil {
		return nil, fmt.Errorf("invalid SSHFP algorithm: %s", err.Error())
	}

	str := strconv.Itoa(int(*algo)) + " "

	digestType, err := parseUint8(record[1])
	if err != nil {
		return nil, fmt.Errorf("invalid digest algorithm: %s", err.Error())
	}

	str += strconv.Itoa(int(*digestType)) + " "

	digest, ok := record[2].(string)
	if !ok {
		return nil, errors.New("SSHFP digest is not a string")
	}

	str += digest + " "

	bytes, err := base64.StdEncoding.DecodeString(digest)
	if err != nil {
		return nil, fmt.Errorf("invalid SSHFP digest: %s", err.Error())
	}

	str += hex.EncodeToString(bytes)

	return &util.GenericNameRecord{
		Name: name,
		RecordData: ncasn.RecordUnion{
			Generic: &ncasn.Generic{
				Type:   dns.TypeSSHFP,
				Target: str,
			},
		},
	}, nil
}

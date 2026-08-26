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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"slices"
	"strings"

	"github.com/namecoin/ncasn"
	"github.com/namecoin/ncasn/benchmark/util"
)

func parseSrv(name *string, value any) ([]ncasn.Record, error) {
	typeOf := reflect.TypeOf(value)
	if typeOf == nil {
		return nil, errors.New("Nil value")
	}

	list, ok := value.([]any)
	if !ok {
		return nil, errors.New("srv is not a slice")
	}

	var ret []ncasn.Record
	for _, elemAny := range list {
		elem, ok := elemAny.([]any)
		if !ok {
			return nil, errors.New("srv element type is not slice")
		}

		if len(elem) < 4 {
			return nil, errors.New("srv array with < 4 parts")
		}
		priority, err := parseUint16(elem[0])
		if err != nil {
			return nil, fmt.Errorf("srv priority is not a uint16: %s", err.Error())
		}

		weight, err := parseUint16(elem[1])
		if err != nil {
			return nil, fmt.Errorf("srv weight is not a uint16: %s", err.Error())
		}

		port, err := parseUint16(elem[2])
		if err != nil {
			return nil, fmt.Errorf("srv port is not a uint16: %s", err.Error())
		}

		target, ok := elem[3].(string)
		if !ok {
			return nil, errors.New("srv target is not a string")
		}

		if len(target) > 255 || !util.IsAscii(target) {
			continue
		}

		if *weight == 0 {
			weight = nil
		}

		ret = append(ret, ncasn.Record{
			Name: name,
			RecordData: ncasn.RecordUnion{
				Srv: &ncasn.SRV{
					Priority: *priority,
					Weight:   weight,
					Port:     *port,
					Target:   target,
				},
			},
		})

		empty := ""
		if *port == 25 && *name == "_smtp._tcp" {
			ret = append(ret, ncasn.Record{
				Name: &empty,
				RecordData: ncasn.RecordUnion{
					Mx: &ncasn.MX{
						Target:   target,
						Priority: *priority,
					},
				},
			})
		}
	}

	return ret, nil
}

func parseDs(name *string, value any) ([]ncasn.Record, error) {
	typeOf := reflect.TypeOf(value)
	if typeOf == nil {
		return nil, errors.New("Nil value")
	}

	kind := typeOf.Kind()
	if kind != reflect.Slice {
		return nil, errors.New("ds is not a slice")
	}

	list := value.([]any)

	var ret []ncasn.Record
	for _, elemAny := range list {
		elem, ok := elemAny.([]any)
		if !ok {
			return nil, errors.New("ds element type is not slice")
		}

		if len(elem) < 4 {
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
			fmt.Println("Unsupported ds key algorithm:", *algo)
			continue
		}

		digestType, err := parseUint8(elem[2])
		if err != nil {
			return nil, fmt.Errorf("ds digest type is not a uint8: %s", err.Error())
		}

		if !slices.Contains(ncasn.DS_DIGEST_TYPES, *digestType) {
			fmt.Println("Unsupported ds digest type:", *digestType)
			continue
		}

		digest, ok := elem[3].(string)
		if !ok {
			return nil, errors.New("ds digest is not a string")
		}
		bytes, err := base64.StdEncoding.DecodeString(digest)
		if err != nil {
			return nil, err
		}
		length := len(bytes)

		var union ncasn.DsDigestUnion
		switch *digestType {
		case 2:
			if length != 32 {
				return nil, fmt.Errorf("Wrong length for SHA-256: %d", length)
			}
			union = ncasn.DsDigestUnion{
				Sha256: &bytes,
			}
		case 4:
			if length != 48 {
				return nil, fmt.Errorf("Wrong length for SHA-384: %d", length)
			}
			union = ncasn.DsDigestUnion{
				Sha384: &bytes,
			}
		case 7:
			if length < 32 || length > 64 {
				return nil, fmt.Errorf("Unsupported digest length: %d", length)
			}
			union = ncasn.DsDigestUnion{
				Unassigned7: &bytes,
			}
		case 8:
			if length < 32 || length > 64 {
				return nil, fmt.Errorf("Unsupported digest length: %d", length)
			}
			union = ncasn.DsDigestUnion{
				Unassigned8: &bytes,
			}
		}

		ret = append(ret, ncasn.Record{
			Name: name,
			RecordData: ncasn.RecordUnion{
				Ds: &ncasn.DS{
					KeyTag:         *key,
					AlgorithmIndex: uint8(ncasn.GetKeyAlgorithmIndex(*algo)),
					Digest:         union,
				},
			},
		})
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
	if length > 4096 {
		return nil, fmt.Errorf("TXT length %d > 4096", length)
	}

	if !util.IsAscii(ret) {
		return nil, errors.New("TXT data is not ASCII")
	}

	return &ret, nil
}

func parseTxt(name *string, value any) ([]ncasn.Record, error) {
	var ret []ncasn.Record

	typeOf := reflect.TypeOf(value)
	if typeOf == nil {
		return nil, errors.New("Nil value")
	}

	kind := typeOf.Kind()
	switch kind {
	case reflect.String:
		parsed, err := parseTxtString(value.(string))
		if err != nil {
			return nil, err
		}
		ret = append(ret, ncasn.Record{
			Name: name,
			RecordData: ncasn.RecordUnion{
				Txt: &ncasn.TXT{
					Content: *parsed,
				},
			},
		})
	case reflect.Slice:
		elemType := typeOf.Elem()
		elemKind := elemType.Kind()
		for _, elem := range value.([]any) {
			switch elemKind {
			case reflect.String:
				parsed, err := parseTxtString(elem.(string))
				if err != nil {
					return nil, err
				}
				ret = append(ret, ncasn.Record{
					Name: name,
					RecordData: ncasn.RecordUnion{
						Txt: &ncasn.TXT{
							Content: *parsed,
						},
					},
				})
			case reflect.Slice:
				var str string
				for _, item := range elem.([]any) {
					itemStr, ok := item.(string)
					if !ok {
						return nil, errors.New("Non-string TXT part")
					}

					length := len(itemStr)
					if length > 255 {
						return nil, fmt.Errorf("TXT part length %d > 255", length)
					}

					str += "\"" + itemStr + "\"" + " "
					length = len(str)
					// + 1 due to the trailing space
					if length > 4097 {
						return nil, errors.New("TXT record too large")
					}
				}

				str = str[:len(str)-1]
				ret = append(ret, ncasn.Record{
					Name: name,
					RecordData: ncasn.RecordUnion{
						Txt: &ncasn.TXT{
							Content: str,
						},
					},
				})
			default:
				return nil, fmt.Errorf("Invalid TXT element type: %s", elemType.String())
			}
		}
	default:
		return nil, fmt.Errorf("Invalid TXT record type: %s", typeOf.String())
	}

	return ret, nil
}

func parseUint8(value any) (*uint8, error) {
	num, ok := value.(json.Number)
	if !ok {
		return nil, errors.New("Value not a number")
	}

	integer, err := num.Int64()
	if err != nil {
		return nil, fmt.Errorf("Value not an integer: %s", err.Error())
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
		return nil, errors.New("Value not a number")
	}

	integer, err := num.Int64()
	if err != nil {
		return nil, fmt.Errorf("Value not an integer: %s", err.Error())
	}

	if integer < 0 || integer > math.MaxUint16 {
		return nil, fmt.Errorf("%d cannot be represented as a uint16", integer)
	}

	cast := uint16(integer)
	return &cast, nil
}

func parseTlsaRecord(name *string, value []any) (*ncasn.Record, error) {
	length := len(value)
	if length < 4 {
		return nil, errors.New("Too few values for a TLSA record")
	}

	usage, err := parseUint8(value[0])
	if err != nil {
		return nil, fmt.Errorf("TLSA certificate usage is not a uint8: %s", err.Error())
	}

	if *usage != 2 {
		return nil, fmt.Errorf("Unsupported TLSA certificate usage: %d", *usage)
	}

	selector, err := parseUint8(value[1])
	if err != nil {
		return nil, fmt.Errorf("TLSA selector is not a uint8: %s", err.Error())
	}

	if *selector > 1 {
		return nil, fmt.Errorf("Unsupported TLSA selector: %d", *selector)
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

	length = len(data)

	var union ncasn.TlsaUnion
	switch *matchingType {
	case 1:
		if length != 32 {
			return nil, fmt.Errorf("SHA-256 TLSA length %d != 32", length)
		}
		union = ncasn.TlsaUnion{
			Sha256: &data,
		}
	case 2:
		if length != 64 {
			return nil, fmt.Errorf("SHA-512 TLSA length %d != 64", length)
		}
		union = ncasn.TlsaUnion{
			Sha512: &data,
		}
	case 3:
		if length < 32 || length > 64 {
			return nil, fmt.Errorf("Unsupported TLSA data length: %d", length)
		}

		union = ncasn.TlsaUnion{
			Unassigned0: &data,
		}
	case 4:
		if length < 32 || length > 64 {
			return nil, fmt.Errorf("Unsupported TLSA data length: %d", length)
		}

		union = ncasn.TlsaUnion{
			Unassigned1: &data,
		}
	default:
		return nil, fmt.Errorf("Unsupported TLSA matching type: %d", *matchingType)
	}

	return &ncasn.Record{
		Name: name,
		RecordData: ncasn.RecordUnion{Tlsa: &ncasn.TLSA{
			Selector:        *selector,
			AssociationData: union,
		}},
	}, nil
}

func parseLocRecord(name *string, value string) (*ncasn.Record, error) {
	data, err := ncasn.StringToLoc(value)
	if err != nil {
		return nil, err
	}

	return &ncasn.Record{Name: name, RecordData: ncasn.RecordUnion{Loc: data}}, nil
}

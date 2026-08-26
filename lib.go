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

package ncasn

import (
	"errors"
	"fmt"
	"reflect"
	"slices"

	"github.com/namecoin/go-asn/asn1"
	"github.com/namecoin/go-asn/uper"
)

type RecordUnion struct {
	A     *A     `asn1:"choice:0"`
	AAAA  *AAAA  `asn1:"choice:1"`
	Srv   *SRV   `asn1:"choice:2"`
	Ds    *DS    `asn1:"choice:3"`
	Txt   *TXT   `asn1:"choice:4"`
	Tlsa  *TLSA  `asn1:"choice:5"`
	Loc   *LOC   `asn1:"choice:6"`
	Mx    *MX    `asn1:"choice:7"`
	Sshfp *SSHFP `asn1:"choice:8"`
	// This is analogous to a DNS ALIAS record, Namecoin's aliases are analogous to DNS CNAME records, which can be specified in Generic instead.
	Alias    *string      `asn1:"choice:9,ia5string,size:0..255"`
	Onion    *OnionV3     `asn1:"choice:10"`
	I2p      *I2PB32      `asn1:"choice:11"`
	I2pLs2   *I2PEB32     `asn1:"choice:12"`
	Generic  *Generic     `asn1:"choice:13"`
	Import   *Import      `asn1:"choice:14"`
	Ipns     *IPNS        `asn1:"choice:15"`
	Hyphanet *HyphanetUSK `asn1:"choice:16"`
}

// This is used in order to avoid manually handling data before Zone.Records, Zone cannot be (un)marshalled directly due to relying on consuming all data to determine the length of Zone.Records, which go-asn cannot do.
type ParsingPlaceholder struct {
	Info *Whois `asn1:"optional"`
}

type Zone struct {
	Info    *Whois
	Records []Record
}

type Record struct {
	// Relative to the base domain, 249 = 255 - 6 (.x.bit).
	// Always non-nil after being unmarshalled, the base domain is represented as an empty string. During (un)marshalling, nils are used to refer to the previous entry.
	Name       *string `asn1:"optional,ia5string,size:0..249"`
	RecordData RecordUnion
}

func PostProcessIpv6(records []Record) {
	for i := range records {
		data := records[i].RecordData.AAAA

		if data == nil || data.ZeroOffset == nil {
			continue
		}

		data.Bytes = slices.Insert(data.Bytes, int(*data.ZeroOffset), make([]byte, 16-len(data.Bytes))...)
	}
}

func UnmarshalRecords(data []byte) (*Zone, error) {
	reader := asn1.NewBitReader(data, false)

	extraData := ParsingPlaceholder{}
	err := uper.UnmarshalValue(reader, reflect.ValueOf(&extraData).Elem(), asn1.FieldOptions{})
	if err != nil {
		return nil, err
	}

	ret := []Record{}
	var lastName *string
	for reader.RemainingBits() > 0 {
		tmp := Record{}
		readerCopy := *reader
		err = uper.UnmarshalValue(reader, reflect.ValueOf(&tmp).Elem(), asn1.FieldOptions{})
		if err != nil {
			// Check if the error is caused by unused trailing bits, ignore it and jump out of the loop if so.
			if readerCopy.RemainingBits() < 8 {
				remaining, err := readerCopy.ReadBits(readerCopy.RemainingBits())
				if err != nil {
					return nil, err
				}

				if remaining != 0 {
					return nil, fmt.Errorf("Unaccounted for bits: %x", remaining)
				}

				// Cannot be a meaningful record, so it must just be the zero padding of the last byte.
				break
			}

			return nil, err
		}
		if tmp.Name == nil {
			tmp.Name = lastName
		}
		ret = append(ret, tmp)
		lastName = tmp.Name
	}

	PostProcessIpv6(ret)
	return &Zone{Info: extraData.Info, Records: ret}, nil
}

func countConsecutiveZeroBytes(slice []byte) uint8 {
	var ret uint8 = 0
	for _, elem := range slice {
		if elem != 0 {
			break
		}

		ret++
	}

	return ret
}

func PreProcessIpv6(records []Record) {
	for i := range records {
		record := records[i].RecordData.AAAA
		if record == nil {
			continue
		}

		oldBytes := record.Bytes
		oldLength := uint8(len(oldBytes))

		longestZeroStart := uint8(0)
		longestZeroLength := uint8(0)

		i := uint8(0)
		for {
			if i >= oldLength-2 || oldLength-i <= longestZeroLength {
				break
			}

			intermediate := countConsecutiveZeroBytes(oldBytes[i:])
			if intermediate > longestZeroLength {
				longestZeroLength = intermediate
				longestZeroStart = i
			}

			if intermediate > 0 {
				i += intermediate
			} else {
				i++
			}
		}

		if longestZeroLength > 2 {
			record.ZeroOffset = &longestZeroStart
			record.Bytes = slices.Delete(oldBytes, int(longestZeroStart), int(longestZeroStart)+int(longestZeroLength))
		}
	}
}

func validateChoice(val reflect.Value) bool {
	for _, field := range val.Fields() {
		if !field.IsNil() {
			return true
		}
	}

	return false
}

func preValidate(records []Record) error {
	if len(records) == 0 {
		return errors.New("len(records) == 0")
	}

	for _, record := range records {
		if record.Name == nil {
			return errors.New("record.Name == nil")
		}

		if !validateChoice(reflect.ValueOf(record)) {
			return fmt.Errorf("Empty CHOICE for %s", *record.Name)
		}
	}

	return nil
}

func MarshalRecords(zone Zone) ([]byte, error) {
	err := preValidate(zone.Records)

	if err != nil {
		return nil, err
	}

	PreProcessIpv6(zone.Records)
	writer := asn1.NewBitWriter(false)

	err = uper.MarshalValue(writer, reflect.ValueOf(ParsingPlaceholder{Info: zone.Info}), asn1.FieldOptions{})
	if err != nil {
		return nil, err
	}

	var lastName *string
	for _, elem := range zone.Records {
		if lastName != nil && *elem.Name == *lastName {
			elem.Name = nil
		} else {
			lastName = elem.Name
		}
		err = uper.MarshalValue(writer, reflect.ValueOf(elem), asn1.FieldOptions{})
		if err != nil {
			return nil, err
		}
	}

	return writer.Bytes(), nil
}

func GetChoice(ref reflect.Value) uint8 {
	for meta, field := range ref.Fields() {
		if !field.IsNil() {
			tag, _ := asn1.ParseTag(meta.Tag.Get("asn1"))
			return uint8(*tag.Choice)
		}
	}

	// Invalid
	return 255
}

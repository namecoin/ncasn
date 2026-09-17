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
	"math/big"
	"reflect"
	"slices"

	"github.com/namecoin/go-asn/aper"
	"github.com/namecoin/go-asn/asn1"
	"github.com/namecoin/go-asn/mixedradix"
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
	// This is analogous to a DNS ALIAS record, Namecoin's aliases are analogous to DNS CNAME records.
	Alias    *string      `asn1:"choice:9,dnsname,size:0..255"`
	Onion    *OnionV3     `asn1:"choice:10"`
	I2p      *I2PB32      `asn1:"choice:11"`
	I2pLs2   *I2PEB32     `asn1:"choice:12"`
	Generic  *Generic     `asn1:"choice:13"`
	Import   *Import      `asn1:"choice:14"`
	Ipns     *IPNS        `asn1:"choice:15"`
	Hyphanet *HyphanetUSK `asn1:"choice:16"`
	Cname    *string      `asn1:"choice:17,dnsname,size:0..255"`
	Ns       *string      `asn1:"choice:18,dnsname,size:0..255"`
	Dname    *string      `asn1:"choice:19,dnsname,size:0..255"`
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
	Name       *string `asn1:"optional,dnsmatcher,size:0..249"`
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

type EncodingType uint8

const (
	MixedRadix EncodingType = iota
	UPER
	APER
)

func (encoding EncodingType) String() string {
	switch encoding {
	case MixedRadix:
		return "Mixed radix"
	case UPER:
		return "UPER"
	case APER:
		return "APER"
	}

	return "Invalid"
}

func (encoding EncodingType) NewReader(data []byte) *asn1.BitReader {
	return asn1.NewBitReader(data, encoding == APER)
}

func (encoding EncodingType) NewWriter() *asn1.BitWriter {
	return asn1.NewBitWriter(encoding == APER)
}

func (encoding EncodingType) UnmarshalValue(reader *asn1.BitReader, v reflect.Value, opts asn1.FieldOptions) error {
	if encoding == UPER {
		return uper.UnmarshalValue(reader, v, opts)
	}

	return aper.UnmarshalValue(reader, v, opts)
}

func (encoding EncodingType) MarshalValue(writer *asn1.BitWriter, v reflect.Value, opts asn1.FieldOptions) error {
	if encoding == UPER {
		return uper.MarshalValue(writer, v, opts)
	}

	return aper.MarshalValue(writer, v, opts)
}

func UnmarshalRecords(data []byte, encoding EncodingType) (*Zone, error) {
	if encoding == MixedRadix {
		return unmarshalMixedRadix(data)
	}

	return unmarshalPacked(data, encoding)
}

func unmarshalPacked(data []byte, encoding EncodingType) (*Zone, error) {
	reader := encoding.NewReader(data)

	extraData := ParsingPlaceholder{}
	err := encoding.UnmarshalValue(reader, reflect.ValueOf(&extraData).Elem(), asn1.FieldOptions{})
	if err != nil {
		return nil, err
	}

	ret := []Record{}
	var lastName *string
	for reader.RemainingBits() > 0 {
		tmp := Record{}
		readerCopy := *reader
		err = encoding.UnmarshalValue(reader, reflect.ValueOf(&tmp).Elem(), asn1.FieldOptions{})
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

func unmarshalMixedRadix(data []byte) (*Zone, error) {
	num := new(big.Int).SetBytes(data)

	extraData := ParsingPlaceholder{}
	err := mixedradix.UnmarshalValue(num, reflect.ValueOf(&extraData).Elem(), asn1.FieldOptions{})
	if err != nil {
		return nil, err
	}

	ret := []Record{}
	zero := big.NewInt(0)
	var lastName *string
	for num.Cmp(zero) == 1 {
		tmp := Record{}
		err = mixedradix.UnmarshalValue(num, reflect.ValueOf(&tmp).Elem(), asn1.FieldOptions{})
		if err != nil {
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

func MarshalRecords(zone Zone, encoding EncodingType) ([]byte, error) {
	if encoding == MixedRadix {
		return marshalMixedRadix(zone)
	}

	return marshalPacked(zone, encoding)
}

func marshalPacked(zone Zone, encoding EncodingType) ([]byte, error) {
	err := preValidate(zone.Records)

	if err != nil {
		return nil, err
	}

	PreProcessIpv6(zone.Records)
	writer := encoding.NewWriter()

	err = encoding.MarshalValue(writer, reflect.ValueOf(ParsingPlaceholder{Info: zone.Info}), asn1.FieldOptions{})
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
		err = encoding.MarshalValue(writer, reflect.ValueOf(elem), asn1.FieldOptions{})
		if err != nil {
			return nil, err
		}
	}

	return writer.Bytes(), nil
}

func marshalMixedRadix(zone Zone) ([]byte, error) {
	err := preValidate(zone.Records)

	if err != nil {
		return nil, err
	}

	PreProcessIpv6(zone.Records)
	num := &asn1.MixedRadixNumber{
		Value: new(big.Int),
		Base:  big.NewInt(1),
	}

	err = mixedradix.MarshalValue(num, reflect.ValueOf(ParsingPlaceholder{Info: zone.Info}), asn1.FieldOptions{})
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
		err = mixedradix.MarshalValue(num, reflect.ValueOf(elem), asn1.FieldOptions{})
		if err != nil {
			return nil, err
		}
	}

	return num.Value.Bytes(), nil
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

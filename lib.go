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

package ncasn

import (
	"cmp"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"slices"
	"strconv"

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
	Ns       *NS          `asn1:"choice:18"`
	Dname    *string      `asn1:"choice:19,dnsname,size:0..255"`
}

// This is used in order to avoid manually handling data before Zone.Records, Zone cannot be (un)marshalled directly due to relying on consuming all data to determine the length of Zone.Records, which go-asn cannot do.
type ParsingPlaceholder struct {
	Info *Whois `asn1:"optional"`
	// Used for hidden subdomains
	Nonce *[]byte `asn1:"optional,size:8"`
}

type Record interface {
	NameString() *string
	Data() RecordUnion
}

type HiddenDomainRecord struct {
	Index      *uint16 `asn1:"optional,size:0..19"`
	RecordData RecordUnion
	name       string // Only used for seed grinding, not stored, must be private to prevent marshalling
}

func (record *HiddenDomainRecord) GetName() string {
	return record.name
}

func (record *HiddenDomainRecord) SetName(name string) {
	record.name = name
}

func (record HiddenDomainRecord) NameString() *string {
	if record.Index == nil {
		return nil
	}

	tmp := strconv.Itoa(int(*record.Index))
	return &tmp
}

func (record HiddenDomainRecord) Data() RecordUnion {
	return record.RecordData
}

type VisibleDomainRecord struct {
	// Relative to the base domain, 249 = 255 - 6 (.x.bit).
	// Always non-nil after being unmarshalled, the base domain is represented as an empty string. During (un)marshalling, nils are used to refer to the previous entry.
	Name       *string `asn1:"optional,dnsmatcher,size:0..249"`
	RecordData RecordUnion
}

func (record VisibleDomainRecord) NameString() *string {
	return record.Name
}

func (record VisibleDomainRecord) Data() RecordUnion {
	return record.RecordData
}

type RecordsUnion struct {
	Visible []VisibleDomainRecord
	Hidden  []HiddenDomainRecord
}

func (union *RecordsUnion) GetRecords() []Record {
	var records []Record
	if union.Hidden == nil {
		records = make([]Record, 0, len(union.Visible))
		for _, record := range union.Visible {
			records = append(records, record)
		}
	} else {
		records = make([]Record, 0, len(union.Hidden))
		for _, record := range union.Hidden {
			records = append(records, record)
		}
	}

	return records
}

type Zone struct {
	Info    *Whois
	Nonce   []byte
	Records RecordsUnion
}

func PostProcessIpv6(records []*AAAA) {
	for _, data := range records {
		if data.ZeroOffset == nil {
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

func getIpv6(records []Record) []*AAAA {
	ipv6 := []*AAAA{}
	for _, record := range records {
		data := record.Data()
		switch {
		case data.AAAA != nil:
			ipv6 = append(ipv6, data.AAAA)
		case data.Ns != nil && data.Ns.Ip != nil && data.Ns.Ip.AAAA != nil:
			ipv6 = append(ipv6, data.Ns.Ip.AAAA)
		}
	}

	return ipv6
}

func unmarshalPacked(data []byte, encoding EncodingType) (*Zone, error) {
	reader := encoding.NewReader(data)

	extraData := ParsingPlaceholder{}
	err := encoding.UnmarshalValue(reader, reflect.ValueOf(&extraData).Elem(), asn1.FieldOptions{})
	if err != nil {
		return nil, err
	}

	var union *RecordsUnion
	var nonce []byte
	if extraData.Nonce == nil {
		union, err = unmarshalPackedVisible(reader, encoding)
	} else {
		union, err = unmarshalPackedHidden(reader, encoding)
		nonce = *extraData.Nonce
	}

	if err != nil {
		return nil, err
	}

	PostProcessIpv6(getIpv6(union.GetRecords()))
	return &Zone{Info: extraData.Info, Records: *union, Nonce: nonce}, nil
}

func unmarshalMixedRadix(data []byte) (*Zone, error) {
	num := new(big.Int).SetBytes(data)

	extraData := ParsingPlaceholder{}
	err := mixedradix.UnmarshalValue(num, reflect.ValueOf(&extraData).Elem(), asn1.FieldOptions{})
	if err != nil {
		return nil, err
	}

	var union *RecordsUnion
	var nonce []byte
	if extraData.Nonce == nil {
		union, err = unmarshalMixedRadixVisible(num)
	} else {
		union, err = unmarshalMixedRadixHidden(num)
		nonce = *extraData.Nonce
	}

	if err != nil {
		return nil, err
	}

	PostProcessIpv6(getIpv6(union.GetRecords()))

	return &Zone{Info: extraData.Info, Records: *union, Nonce: nonce}, nil
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

func PreProcessIpv6(records []*AAAA) {
	for _, record := range records {
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

func preValidate(records RecordsUnion) error {
	cast := records.GetRecords()

	if len(cast) == 0 {
		return errors.New("len(records) == 0")
	}

	for _, record := range cast {
		err := validateRecord(record)
		if err != nil {
			return err
		}
	}

	return nil
}

func validateRecord(record Record) error {
	name := record.NameString()
	if name == nil {
		return errors.New("record.NameString() == nil")
	}

	if !validateChoice(reflect.ValueOf(record.Data())) {
		return fmt.Errorf("Empty CHOICE for %s", *name)
	}

	return nil
}

func MarshalRecords(zone Zone, encoding EncodingType) ([]byte, error) {
	err := preValidate(zone.Records)

	if err != nil {
		return nil, err
	}

	PreProcessIpv6(getIpv6(zone.Records.GetRecords()))

	// Sort in order to group subdomains, maximizing name elision
	if zone.Records.Hidden == nil {
		slices.SortFunc(zone.Records.Visible, func(a VisibleDomainRecord, b VisibleDomainRecord) int {
			return cmp.Compare(*a.Name, *b.Name)
		})
	} else {
		slices.SortFunc(zone.Records.Hidden, func(a HiddenDomainRecord, b HiddenDomainRecord) int {
			return cmp.Compare(*a.Index, *b.Index)
		})
	}

	if encoding == MixedRadix {
		return marshalMixedRadix(zone)
	}

	return marshalPacked(zone, encoding)
}

func marshalPacked(zone Zone, encoding EncodingType) ([]byte, error) {
	writer := encoding.NewWriter()

	var nonce *[]byte
	if zone.Nonce != nil {
		nonce = &zone.Nonce
	}

	err := encoding.MarshalValue(writer, reflect.ValueOf(ParsingPlaceholder{Info: zone.Info, Nonce: nonce}), asn1.FieldOptions{})
	if err != nil {
		return nil, err
	}

	if zone.Nonce == nil {
		return marshalPackedVisible(writer, encoding, &zone.Records)
	}
	return marshalPackedHidden(writer, encoding, &zone.Records)
}

func marshalMixedRadix(zone Zone) ([]byte, error) {
	num := &asn1.MixedRadixNumber{
		Value: new(big.Int),
		Base:  big.NewInt(1),
	}

	var nonce *[]byte
	if zone.Nonce != nil {
		nonce = &zone.Nonce
	}

	err := mixedradix.MarshalValue(num, reflect.ValueOf(ParsingPlaceholder{Info: zone.Info, Nonce: nonce}), asn1.FieldOptions{})
	if err != nil {
		return nil, err
	}

	if zone.Nonce == nil {
		return marshalMixedRadixVisible(num, &zone.Records)
	}

	return marshalMixedRadixHidden(num, &zone.Records)
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

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
	"fmt"
	"math/big"
	"reflect"

	"github.com/namecoin/go-asn/asn1"
	"github.com/namecoin/go-asn/mixedradix"
)

func unmarshalMixedRadixHidden(num *big.Int) (*RecordsUnion, error) {
	ret := []HiddenDomainRecord{}
	zero := big.NewInt(0)
	var lastName *uint16
	for num.Cmp(zero) == 1 {
		var tmp HiddenDomainRecord
		err := mixedradix.UnmarshalValue(num, reflect.ValueOf(&tmp).Elem(), asn1.FieldOptions{})
		if err != nil {
			return nil, err
		}
		if tmp.Index == nil {
			tmp.Index = lastName
		}
		ret = append(ret, tmp)
		lastName = tmp.Index
	}

	return &RecordsUnion{Hidden: ret}, nil
}

func unmarshalMixedRadixVisible(num *big.Int) (*RecordsUnion, error) {
	ret := []VisibleDomainRecord{}
	zero := big.NewInt(0)
	var lastName *string
	for num.Cmp(zero) == 1 {
		var tmp VisibleDomainRecord
		err := mixedradix.UnmarshalValue(num, reflect.ValueOf(&tmp).Elem(), asn1.FieldOptions{})
		if err != nil {
			return nil, err
		}
		if tmp.Name == nil {
			tmp.Name = lastName
		}
		ret = append(ret, tmp)
		lastName = tmp.Name
	}

	return &RecordsUnion{Visible: ret}, nil
}

func unmarshalPackedHidden(reader *asn1.BitReader, encoding EncodingType) (*RecordsUnion, error) {
	ret := []HiddenDomainRecord{}
	var lastName *uint16
	for reader.RemainingBits() > 0 {
		var tmp HiddenDomainRecord
		readerCopy := *reader
		err := encoding.UnmarshalValue(reader, reflect.ValueOf(&tmp).Elem(), asn1.FieldOptions{})
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
		if tmp.Index == nil {
			tmp.Index = lastName
		}
		ret = append(ret, tmp)
		lastName = tmp.Index
	}

	return &RecordsUnion{Hidden: ret}, nil
}

func unmarshalPackedVisible(reader *asn1.BitReader, encoding EncodingType) (*RecordsUnion, error) {
	ret := []VisibleDomainRecord{}
	var lastName *string
	for reader.RemainingBits() > 0 {
		var tmp VisibleDomainRecord
		readerCopy := *reader
		err := encoding.UnmarshalValue(reader, reflect.ValueOf(&tmp).Elem(), asn1.FieldOptions{})
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

	return &RecordsUnion{Visible: ret}, nil
}

func marshalPackedHidden(writer *asn1.BitWriter, encoding EncodingType, records *RecordsUnion) ([]byte, error) {
	var lastName *uint16
	for _, elem := range records.Hidden {
		if lastName != nil && *elem.Index == *lastName {
			elem.Index = nil
		} else {
			lastName = elem.Index
		}
		err := encoding.MarshalValue(writer, reflect.ValueOf(elem), asn1.FieldOptions{})
		if err != nil {
			return nil, err
		}
	}

	return writer.Bytes(), nil
}

func marshalPackedVisible(writer *asn1.BitWriter, encoding EncodingType, records *RecordsUnion) ([]byte, error) {
	var lastName *string
	for _, elem := range records.Visible {
		if lastName != nil && *elem.Name == *lastName {
			elem.Name = nil
		} else {
			lastName = elem.Name
		}
		err := encoding.MarshalValue(writer, reflect.ValueOf(elem), asn1.FieldOptions{})
		if err != nil {
			return nil, err
		}
	}

	return writer.Bytes(), nil
}

func marshalMixedRadixHidden(num *asn1.MixedRadixNumber, records *RecordsUnion) ([]byte, error) {
	var lastName *uint16
	for _, elem := range records.Hidden {
		if lastName != nil && *elem.Index == *lastName {
			elem.Index = nil
		} else {
			lastName = elem.Index
		}
		err := mixedradix.MarshalValue(num, reflect.ValueOf(elem), asn1.FieldOptions{})
		if err != nil {
			return nil, err
		}
	}

	return num.Value.Bytes(), nil
}

func marshalMixedRadixVisible(num *asn1.MixedRadixNumber, records *RecordsUnion) ([]byte, error) {
	var lastName *string
	for _, elem := range records.Visible {
		if lastName != nil && *elem.Name == *lastName {
			elem.Name = nil
		} else {
			lastName = elem.Name
		}
		err := mixedradix.MarshalValue(num, reflect.ValueOf(elem), asn1.FieldOptions{})
		if err != nil {
			return nil, err
		}
	}

	return num.Value.Bytes(), nil
}

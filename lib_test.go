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

package ncasn_test

import (
	"reflect"
	"slices"
	"testing"

	"github.com/namecoin/go-asn/asn1"
	"github.com/namecoin/go-asn/uper"
	"github.com/sofia-nep/ncasn"
)

var SAMPLE_AAAA = ncasn.AAAA{
	Bytes: []byte{
		1, 1, 1, 0,
		0, 0, 0, 1,
		0, 0, 0, 0,
		0, 0, 1, 1,
	},
}

var SAMPLE_OFFSET uint8 = 8

var SAMPLE_PROCESSED = ncasn.AAAA{
	ZeroOffset: &SAMPLE_OFFSET,
	Bytes: []byte{
		1, 1, 1, 0,
		0, 0, 0, 1,
		1, 1,
	},
}

var SAMPLE_NAME0 = "abc"
var SAMPLE_NAME1 = "cba"

func TestPostProcessIpv6(t *testing.T) {
	sampleCopy := SAMPLE_PROCESSED
	record := ncasn.Record{
		Name:       &SAMPLE_NAME0,
		RecordData: ncasn.RecordUnion{AAAA: &sampleCopy},
	}

	ncasn.PostProcessIpv6([]ncasn.Record{record})

	if !slices.Equal(sampleCopy.Bytes, SAMPLE_AAAA.Bytes) {
		t.Error("Bytes != sample")
	}
}

type ChoiceTest struct {
	Zero *uint8 `asn1:"choice:0"`
	One  *uint8 `asn1:"choice:1"`
}

func TestGetChoice(t *testing.T) {
	zero := ChoiceTest{Zero: &SAMPLE_OFFSET}
	one := ChoiceTest{One: &SAMPLE_OFFSET}

	if ncasn.GetChoice(reflect.ValueOf(zero)) != 0 {
		t.Error("Choice != 0")
	}

	if ncasn.GetChoice(reflect.ValueOf(one)) != 1 {
		t.Error("Choice != 1")
	}
}

func TestPreProcessIpv6(t *testing.T) {
	sampleCopy := SAMPLE_AAAA
	record := ncasn.Record{
		Name:       &SAMPLE_NAME0,
		RecordData: ncasn.RecordUnion{AAAA: &sampleCopy},
	}
	ncasn.PreProcessIpv6([]ncasn.Record{record})

	if !slices.Equal(sampleCopy.Bytes, SAMPLE_PROCESSED.Bytes) {
		t.Error("Bytes != sample")
	}

	if *sampleCopy.ZeroOffset != SAMPLE_OFFSET {
		t.Error("Offset != sample")
	}
}

func TestNameOmission(t *testing.T) {
	records := []ncasn.Record{
		{Name: &SAMPLE_NAME0, RecordData: ncasn.RecordUnion{AAAA: &SAMPLE_AAAA}},
		{Name: &SAMPLE_NAME0, RecordData: ncasn.RecordUnion{AAAA: &SAMPLE_AAAA}},
		{Name: &SAMPLE_NAME0, RecordData: ncasn.RecordUnion{AAAA: &SAMPLE_AAAA}},
		{Name: &SAMPLE_NAME1, RecordData: ncasn.RecordUnion{AAAA: &SAMPLE_AAAA}},
		{Name: &SAMPLE_NAME1, RecordData: ncasn.RecordUnion{AAAA: &SAMPLE_AAAA}},
		{Name: &SAMPLE_NAME0, RecordData: ncasn.RecordUnion{AAAA: &SAMPLE_AAAA}},
	}

	names := []*string{
		&SAMPLE_NAME0,
		nil,
		nil,
		&SAMPLE_NAME1,
		nil,
		&SAMPLE_NAME0,
	}

	encoded, err := ncasn.MarshalRecords(ncasn.Zone{Records: records, Info: nil})
	if err != nil {
		t.Fatalf("err != nil: %s", err.Error())
	}

	reader := asn1.NewBitReader(encoded, false)

	// Skip data
	var zone ncasn.ParsingPlaceholder
	err = uper.UnmarshalValue(reader, reflect.ValueOf(&zone).Elem(), asn1.FieldOptions{})
	if err != nil {
		t.Fatalf("err != nil: %s", err.Error())
	}

	for i := range records {
		var record ncasn.Record
		err = uper.UnmarshalValue(reader, reflect.ValueOf(&record).Elem(), asn1.FieldOptions{})
		if err != nil {
			t.Fatalf("err != nil: %s", err.Error())
		}

		lhsNil := record.Name == nil
		rhsNil := names[i] == nil
		if lhsNil != rhsNil {
			t.Errorf("Different nullability at %d: %t vs %t", i, lhsNil, rhsNil)
		}

		if !(lhsNil || rhsNil) && *record.Name != *names[i] {
			t.Errorf("Name %d != sample: %s != %s", i, *record.Name, *names[i])
		}
	}
}

func TestNameAddition(t *testing.T) {
	records := []ncasn.Record{
		{Name: &SAMPLE_NAME0, RecordData: ncasn.RecordUnion{AAAA: &SAMPLE_AAAA}},
		{Name: &SAMPLE_NAME0, RecordData: ncasn.RecordUnion{AAAA: &SAMPLE_AAAA}},
		{Name: &SAMPLE_NAME0, RecordData: ncasn.RecordUnion{AAAA: &SAMPLE_AAAA}},
		{Name: &SAMPLE_NAME1, RecordData: ncasn.RecordUnion{AAAA: &SAMPLE_AAAA}},
		{Name: &SAMPLE_NAME1, RecordData: ncasn.RecordUnion{AAAA: &SAMPLE_AAAA}},
		{Name: &SAMPLE_NAME0, RecordData: ncasn.RecordUnion{AAAA: &SAMPLE_AAAA}},
	}

	encoded, err := ncasn.MarshalRecords(ncasn.Zone{Records: records, Info: nil})
	if err != nil {
		t.Fatalf("err != nil: %s", err.Error())
	}

	decoded, err := ncasn.UnmarshalRecords(encoded)
	if err != nil {
		t.Fatalf("err != nil: %s", err.Error())
	}

	for i, decodedRecord := range decoded.Records {
		if decodedRecord.Name == nil {
			t.Fatalf("Nil name at %d", i)
		}

		if *decodedRecord.Name != *records[i].Name {
			t.Errorf("Name %d != sample: %s != %s", i, *decodedRecord.Name, *records[i].Name)
		}
	}
}

func TestRecordCount(t *testing.T) {
	records := []ncasn.Record{
		{Name: &SAMPLE_NAME0, RecordData: ncasn.RecordUnion{AAAA: &SAMPLE_AAAA}},
		{Name: &SAMPLE_NAME0, RecordData: ncasn.RecordUnion{AAAA: &SAMPLE_AAAA}},
		{Name: &SAMPLE_NAME0, RecordData: ncasn.RecordUnion{AAAA: &SAMPLE_AAAA}},
		{Name: &SAMPLE_NAME1, RecordData: ncasn.RecordUnion{AAAA: &SAMPLE_AAAA}},
		{Name: &SAMPLE_NAME1, RecordData: ncasn.RecordUnion{AAAA: &SAMPLE_AAAA}},
		{Name: &SAMPLE_NAME0, RecordData: ncasn.RecordUnion{AAAA: &SAMPLE_AAAA}},
	}

	encoded, err := ncasn.MarshalRecords(ncasn.Zone{Records: records, Info: nil})
	if err != nil {
		t.Fatalf("err != nil: %s", err.Error())
	}

	decoded, err := ncasn.UnmarshalRecords(encoded)
	if err != nil {
		t.Fatalf("err != nil: %s", err.Error())
	}

	sampleLen := len(records)
	actualLen := len(decoded.Records)
	if len(records) != len(decoded.Records) {
		t.Errorf("Count != sample: %d != %d", actualLen, sampleLen)
	}
}

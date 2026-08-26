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
	"slices"
	"testing"

	"github.com/namecoin/ncasn"
)

const SAMPLE_I2P = "ukeu3k5oycgaauneqgtnvselmt4yemvoilkln7jpvamvfx7dnkdq.b32.i2p"

var SAMPLE_I2P_RECORD = ncasn.I2PB32{
	Bytes: []byte{
		0xa2, 0x89, 0x4d, 0xab,
		0xae, 0xc0, 0x8c, 0x00,
		0x51, 0xa4, 0x81, 0xa6,
		0xda, 0xc8, 0x8b, 0x64,
		0xf9, 0x82, 0x32, 0xae,
		0x42, 0xd4, 0xb6, 0xfd,
		0x2f, 0xa8, 0x19, 0x52,
		0xdf, 0xe3, 0x6a, 0x87,
	},
}

func TestI2pRecordFromDomain(t *testing.T) {
	record, extended, err := ncasn.I2pRecordFromDomain(SAMPLE_I2P)
	if extended != nil {
		t.Fatal("Domain recognized as EB32.")
	}

	if err != nil {
		t.Fatalf("err != nil: %s", err.Error())
	}

	if !slices.Equal(record.Bytes, SAMPLE_I2P_RECORD.Bytes) {
		t.Error("record != sample")
	}
}

func TestI2pDomainFromRecord(t *testing.T) {
	domain := SAMPLE_I2P_RECORD.ToDomain()
	if domain != SAMPLE_I2P {
		t.Errorf("domain != sample: %s != %s", domain, SAMPLE_I2P)
	}
}

const SAMPLE_EB32 = "t34mzpdaws3ljqsodjj737iysfxagsr45m2ao43vlzi3h6nqj2ehd2ri.b32.i2p"

var SAMPLE_EB32_RECORD = ncasn.I2PEB32{
	PublicSigType:  7,
	BlindedSigType: 11,
	Secret:         false,
	ClientAuth:     false,
	Key: []byte{
		0xbc, 0x60, 0xb4, 0xb6,
		0xb4, 0xc2, 0x4e, 0x1a,
		0x53, 0xfd, 0xfd, 0x18,
		0x91, 0x6e, 0x03, 0x4a,
		0x3c, 0xeb, 0x34, 0x07,
		0x73, 0x75, 0x5e, 0x51,
		0xb3, 0xf9, 0xb0, 0x4e,
		0x88, 0x71, 0xea, 0x28,
	},
}

func TestI2pEB32RecordFromDomain(t *testing.T) {
	old, extended, err := ncasn.I2pRecordFromDomain(SAMPLE_EB32)
	if old != nil {
		t.Fatal("Domain recognized as B32.")
	}

	if err != nil {
		t.Fatalf("err != nil: %s", err.Error())
	}

	if extended.Secret != SAMPLE_EB32_RECORD.Secret {
		t.Error("Secret != sample")
	}

	if extended.ClientAuth != SAMPLE_EB32_RECORD.ClientAuth {
		t.Error("ClientAuth != sample")
	}

	if extended.PublicSigType != SAMPLE_EB32_RECORD.PublicSigType {
		t.Error("PublicSigType != sample")
	}

	if extended.BlindedSigType != SAMPLE_EB32_RECORD.BlindedSigType {
		t.Error("BlindedSigType != sample")
	}

	if !slices.Equal(extended.Key, SAMPLE_EB32_RECORD.Key) {
		t.Error("Key != sample")
	}
}

func TestI2pEB32RecordToDomain(t *testing.T) {
	addr := SAMPLE_EB32_RECORD.ToDomain()
	if addr != SAMPLE_EB32 {
		t.Errorf("Domain != sample: %s != %s", addr, SAMPLE_EB32)
	}
}

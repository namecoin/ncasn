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

const SAMPLE_IPNS = "k51qzi5uqu5dl965cvc69wz19638leinzz9yj931iuang4w7cax0nmnf3e9osc"
const SAMPLE_IPNS_PREFIXED = "/ipns/" + SAMPLE_IPNS

var SAMPLE_IPNS_BYTES = []byte{
	0xcb, 0x7c, 0xce, 0x1c,
	0x54, 0xbf, 0xe7, 0xc3,
	0xac, 0x98, 0x1e, 0x40,
	0xd8, 0xdf, 0xce, 0xfc,
	0x76, 0xb2, 0xa6, 0x70,
	0x40, 0x20, 0xc9, 0x74,
	0xdb, 0xed, 0xfd, 0x6a,
	0xba, 0x79, 0x4f, 0xbc,
}

func TestToIpnsRecord(t *testing.T) {
	rec, err := ncasn.IpnsToRecord(SAMPLE_IPNS)
	if err != nil {
		t.Fatalf("err != nil: %s", err.Error())
	}

	recPrefixed, err := ncasn.IpnsToRecord(SAMPLE_IPNS_PREFIXED)
	if err != nil {
		t.Fatalf("err != nil: %s", err.Error())
	}

	if !slices.Equal(rec.Key, recPrefixed.Key) {
		t.Error("Prefixed and non-prefixed keys have different key bytes")
	}

	if !slices.Equal(rec.Key, SAMPLE_IPNS_BYTES) {
		t.Error("Key != sample")
	}
}

func TestFromIpnsRecord(t *testing.T) {
	record := ncasn.IPNS{Key: SAMPLE_IPNS_BYTES}
	key := record.ToString()
	if key != SAMPLE_IPNS_PREFIXED {
		t.Errorf("String != sample: %s != %s", key, SAMPLE_IPNS)
	}
}

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

const SAMPLE_USK = "USK@5hH~39FtjA7A9~VXWtBKI~prUDTuJZURudDG0xFn3KA,GDgRGt5f6xqbmo-WraQtU54x4H~871Sho9Hz6hC-0RA,AQACAAE/Search/17/"

var SAMPLE_HYPHA = ncasn.HyphanetUSK{
	KeyHash: []byte{
		0xe6, 0x11, 0xfe, 0xdf,
		0xd1, 0x6d, 0x8c, 0x0e,
		0xc0, 0xf7, 0xe5, 0x57,
		0x5a, 0xd0, 0x4a, 0x23,
		0xea, 0x6b, 0x50, 0x34,
		0xee, 0x25, 0x95, 0x11,
		0xb9, 0xd0, 0xc6, 0xd3,
		0x11, 0x67, 0xdc, 0xa0,
	},
	Key: []byte{
		0x18, 0x38, 0x11, 0x1a,
		0xde, 0x5f, 0xeb, 0x1a,
		0x9b, 0x9a, 0x8f, 0xd6,
		0xad, 0xa4, 0x2d, 0x53,
		0x9e, 0x31, 0xe0, 0x7f,
		0xbc, 0xef, 0x54, 0xa1,
		0xa3, 0xd1, 0xf3, 0xea,
		0x10, 0xbf, 0xd1, 0x10,
	},
	Extra:   []byte{0x01, 0x00, 0x02, 0x00, 0x01},
	Name:    "Search",
	Edition: 17,
}

func TestUSKRecordFromKey(t *testing.T) {
	data, err := ncasn.USKRecordFromKey(SAMPLE_USK)
	if err != nil {
		t.Fatalf("err != nil: %s", err.Error())
	}

	if !slices.Equal(data.KeyHash, SAMPLE_HYPHA.KeyHash) {
		t.Error("KeyHash != sample")
	}

	if !slices.Equal(data.Key, SAMPLE_HYPHA.Key) {
		t.Error("Key != sample")
	}

	if !slices.Equal(data.Extra, SAMPLE_HYPHA.Extra) {
		t.Error("Extra != sample")
	}

	if data.Name != SAMPLE_HYPHA.Name {
		t.Error("Name != sample")
	}

	if data.Edition != SAMPLE_HYPHA.Edition {
		t.Error("Edition != sample")
	}
}

func TestUSKRecordToKey(t *testing.T) {
	if SAMPLE_HYPHA.ToKey() != SAMPLE_USK {
		t.Error("USK != sample")
	}
}

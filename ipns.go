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
	"encoding/hex"
	"slices"
	"strings"

	"github.com/ipfs/go-cid"
	"github.com/multiformats/go-multibase"
	"github.com/multiformats/go-multihash"
)

var UNKNOWN_IPNS_HEADER = []byte{0x08, 0x01, 0x12, 0x20}

func IpnsToRecord(key string) (*IPNS, error) {
	key = strings.TrimPrefix(key, "/ipns/")

	decoded, err := cid.Decode(key)
	if err != nil {
		return nil, err
	}

	mh := decoded.Hash().HexString()
	bytes, err := hex.DecodeString(mh)

	if err != nil {
		return nil, err
	}

	decodedHash, err := multihash.Decode(bytes)
	if err != nil {
		return nil, err
	}

	return &IPNS{Key: decodedHash.Digest[4:]}, nil
}

func (record *IPNS) ToString() string {
	ret := "/ipns/"

	hash, _ := multihash.Encode(slices.Concat(UNKNOWN_IPNS_HEADER, record.Key), multibase.Identity)
	encoded, _ := cid.NewCidV1(0x72, hash).StringOfBase(multibase.Base36)

	return ret + encoded
}

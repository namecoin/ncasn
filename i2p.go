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
	"encoding/base32"
	"errors"
	"fmt"
	"hash/crc32"
	"slices"
	"strings"
)

var I2P_ENCODING = base32.StdEncoding.WithPadding(base32.NoPadding)

func I2pRecordFromDomain(domain string) (*I2PB32, *I2PEB32, error) {
	b32, found := strings.CutSuffix(domain, ".b32.i2p")
	if !found {
		return nil, nil, errors.New("Only .b32.i2p domains are supported.")
	}

	b32 = strings.ToUpper(b32)

	bytes, err := I2P_ENCODING.DecodeString(b32)
	if err != nil {
		return nil, nil, err
	}

	length := len(bytes)

	if length == 32 {
		return &I2PB32{Bytes: bytes}, nil, nil
	}

	if length != 35 {
		return nil, nil, fmt.Errorf("Unsupported I2P byte length %d.", length)
	}

	csum := crc32.ChecksumIEEE(bytes[3:])
	flags := bytes[0] ^ byte(csum)
	if flags&1 != 0 {
		return nil, nil, errors.New("Two byte sigtypes are not supported.")
	}

	return nil, &I2PEB32{
		PublicSigType:  bytes[1] ^ byte(csum>>8),
		BlindedSigType: bytes[2] ^ byte(csum>>16),
		Secret:         flags&2 == 1,
		ClientAuth:     flags&4 == 1,
		Key:            bytes[3:],
	}, nil
}

func (record *I2PB32) ToDomain() string {
	return strings.ToLower(I2P_ENCODING.EncodeToString(record.Bytes)) + ".b32.i2p"
}

func (record *I2PEB32) ToDomain() string {
	var flags byte
	if record.Secret {
		flags |= 1 << 2
	}

	if record.ClientAuth {
		flags |= 1 << 4
	}

	data := slices.Concat([]byte{flags, record.PublicSigType, record.BlindedSigType}, record.Key)
	csum := crc32.ChecksumIEEE(record.Key)
	data[0] ^= byte(csum)
	data[1] ^= byte(csum >> 8)
	data[2] ^= byte(csum >> 16)

	return strings.ToLower(I2P_ENCODING.EncodeToString(data)) + ".b32.i2p"
}

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
	"encoding/base32"
	"errors"
	"fmt"
	"hash/crc32"
	"slices"
	"strings"
)

var I2P_ENCODING = base32.StdEncoding.WithPadding(base32.NoPadding)

var ErrNonB32Domain = errors.New("only .b32.i2p domains are supported")
var ErrTwoByteSigtype = errors.New("two byte sigtypes are not supported")
var ErrWrongByteLength = errors.New("unsupported I2P byte length")

func I2pRecordFromDomain(domain string) (*I2PB32, *I2PEB32, error) {
	b32, found := strings.CutSuffix(domain, ".b32.i2p")
	if !found {
		return nil, nil, ErrNonB32Domain
	}

	b32 = strings.ToUpper(b32)

	bytes, err := I2P_ENCODING.DecodeString(b32)
	if err != nil {
		return nil, nil, err
	}

	length := len(bytes)

	expectedLen := 32
	if length == expectedLen {
		return &I2PB32{Bytes: bytes}, nil, nil
	}

	expectedLen = 35
	if length != expectedLen {
		return nil, nil, fmt.Errorf("%w: %d", ErrWrongByteLength, length)
	}

	csum := crc32.ChecksumIEEE(bytes[3:])
	// Intentionally truncated
	trunc := byte(csum) // nolint: gosec

	flags := bytes[0] ^ trunc
	if flags&1 != 0 {
		return nil, nil, ErrTwoByteSigtype
	}

	var ret I2PEB32

	var offset uint32 = 8

	// Intentionally truncated
	trunc = byte(csum >> offset) // nolint: gosec
	ret.PublicSigType = bytes[1] ^ trunc

	offset = 16
	// Intentionally truncated
	trunc = byte(csum >> offset) // nolint: gosec
	ret.BlindedSigType = bytes[2] ^ trunc

	var pos byte = 2

	ret.Secret = flags&pos == 1

	pos = 4
	ret.ClientAuth = flags&pos == 1

	ret.Key = bytes[3:]

	return nil, &ret, nil
}

func (record *I2PB32) ToDomain() string {
	return strings.ToLower(I2P_ENCODING.EncodeToString(record.Bytes)) + ".b32.i2p"
}

func (record *I2PEB32) ToDomain() string {
	var flags byte

	secretPos := 2
	if record.Secret {
		flags |= 1 << secretPos
	}

	authPos := 4
	if record.ClientAuth {
		flags |= 1 << authPos
	}

	data := slices.Concat([]byte{flags, record.PublicSigType, record.BlindedSigType}, record.Key)
	csum := crc32.ChecksumIEEE(record.Key)

	var offset uint32 = 8
	// Intentionally truncated
	data[0] ^= byte(csum)           // nolint: gosec
	data[1] ^= byte(csum >> offset) // nolint: gosec

	offset = 16
	data[2] ^= byte(csum >> offset) // nolint: gosec

	return strings.ToLower(I2P_ENCODING.EncodeToString(data)) + ".b32.i2p"
}

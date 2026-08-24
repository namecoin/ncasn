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

package zone

import (
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/sofia-nep/ncasn"
)

func parseSrv(fields []string) (*ncasn.RecordUnion, error) {
	if len(fields) < 8 {
		return nil, errors.New("Invalid SRV record")
	}
	priority, err := strconv.ParseUint(fields[4], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("Invalid SRV priority: %s", err.Error())
	}

	weightNum, err := strconv.ParseUint(fields[5], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("Invalid SRV weight: %s", err.Error())
	}
	// Reduce storage usage by assuming most weights will be 0
	var weight *uint16
	if weightNum != 0 {
		weight16 := uint16(weightNum)
		weight = &weight16
	}

	port, err := strconv.ParseUint(fields[6], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("Invalid SRV port: %s", err.Error())
	}

	return &ncasn.RecordUnion{Srv: &ncasn.SRV{
		Priority: uint16(priority),
		Weight:   weight,
		Port:     uint16(port),
		Target:   fields[7],
	}}, nil
}

func parseDs(fields []string) (*ncasn.RecordUnion, error) {
	if len(fields) < 8 {
		return nil, fmt.Errorf("Invalid DS record: %s", strings.Join(fields[4:], " "))
	}

	keyTag, err := strconv.ParseUint(fields[4], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("Invalid DS key tag: %s", err.Error())
	}

	algorithm, err := strconv.ParseUint(fields[5], 10, 8)
	if err != nil {
		return nil, fmt.Errorf("Invalid DS algorithm: %s", err.Error())
	}

	if !slices.Contains(ncasn.DS_KEY_ALGOS, uint8(algorithm)) {
		fmt.Println("Unsupported DS algorithm:", algorithm)
		return nil, nil
	}

	digestType, err := strconv.ParseUint(fields[6], 10, 8)
	if err != nil {
		return nil, fmt.Errorf("Invalid DS digest type: %s", err.Error())
	}

	if !slices.Contains(ncasn.DS_DIGEST_TYPES, uint8(digestType)) {
		return nil, fmt.Errorf("Unsupporteed DS digest type: %d", digestType)
	}

	bytes, err := hex.DecodeString(strings.ToLower(fields[7]))
	if err != nil {
		return nil, err
	}
	length := len(bytes)

	switch digestType {
	case 2:
		if length != 32 {
			return nil, fmt.Errorf("Invalid digest length %d for SHA-256", length)
		}
		return &ncasn.RecordUnion{Ds: &ncasn.DS{
			KeyTag:         uint16(keyTag),
			AlgorithmIndex: uint8(ncasn.GetKeyAlgorithmIndex(uint8(algorithm))),
			Digest:         ncasn.DsDigestUnion{Sha256: &bytes},
		}}, nil
	case 4:
		if length != 48 {
			return nil, fmt.Errorf("Invalid digest length %d for SHA-384", length)
		}
		return &ncasn.RecordUnion{Ds: &ncasn.DS{
			KeyTag:         uint16(keyTag),
			AlgorithmIndex: uint8(ncasn.GetKeyAlgorithmIndex(uint8(algorithm))),
			Digest:         ncasn.DsDigestUnion{Sha384: &bytes},
		}}, nil
	case 7:
		if length < 32 || length > 64 {
			return nil, fmt.Errorf("Invalid digest length %d for type 7", length)
		}
		return &ncasn.RecordUnion{Ds: &ncasn.DS{
			KeyTag:         uint16(keyTag),
			AlgorithmIndex: uint8(ncasn.GetKeyAlgorithmIndex(uint8(algorithm))),
			Digest:         ncasn.DsDigestUnion{Unassigned7: &bytes},
		}}, nil
	case 8:
		if length < 32 || length > 64 {
			return nil, fmt.Errorf("Invalid digest length %d for type 8", length)
		}
		return &ncasn.RecordUnion{Ds: &ncasn.DS{
			KeyTag:         uint16(keyTag),
			AlgorithmIndex: uint8(ncasn.GetKeyAlgorithmIndex(uint8(algorithm))),
			Digest:         ncasn.DsDigestUnion{Unassigned8: &bytes},
		}}, nil
	}

	return nil, fmt.Errorf("Unsupported digest type %d", digestType)
}

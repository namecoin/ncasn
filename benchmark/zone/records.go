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

package zone

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/namecoin/ncasn"
	"github.com/namecoin/ncasn/benchmark/util"
)

func parseSrv(fields []string) (*ncasn.RecordUnion, error) {
	validSize := 8
	if len(fields) < validSize {
		return nil, errors.New("invalid SRV record")
	}

	priority, err := strconv.ParseUint(fields[4], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid SRV priority: %s", err.Error())
	}

	weightNum, err := strconv.ParseUint(fields[5], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid SRV weight: %s", err.Error())
	}
	// Reduce storage usage by assuming most weights will be 0
	var weight *uint16

	if weightNum != 0 {
		weight16 := uint16(weightNum)
		weight = &weight16
	}

	port, err := strconv.ParseUint(fields[6], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid SRV port: %s", err.Error())
	}

	return &ncasn.RecordUnion{Srv: &ncasn.SRV{
		Data: ncasn.SRVData{
			Priority: uint16(priority),
			Weight:   weight,
			Port:     uint16(port),
			Target:   fields[7],
		},
	}}, nil
}

func processSrv(subdomain string, record *ncasn.SRV) string {
	meta := ncasn.SrvNameToMeta(subdomain)
	if meta != nil {
		split := strings.Split(subdomain, ".")

		baseLabels := 2
		if len(split) <= baseLabels {
			subdomain = ""
		} else {
			subdomain = strings.Join(split[2:], ".")
		}

		record.Meta = meta
	}

	return subdomain
}

func parseDs(fields []string) (*ncasn.RecordUnion, error) {
	validSize := 8
	if len(fields) < validSize {
		return nil, fmt.Errorf("invalid DS record: %s", strings.Join(fields[4:], " "))
	}

	keyTag, err := strconv.ParseUint(fields[4], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid DS key tag: %w", err)
	}

	algorithm, err := strconv.ParseUint(fields[5], 10, 8)
	if err != nil {
		return nil, fmt.Errorf("invalid DS algorithm: %w", err)
	}

	if !slices.Contains(ncasn.DS_KEY_ALGOS, uint8(algorithm)) {
		fmt.Println("unsupported DS algorithm:", algorithm)

		return nil, nil
	}

	digestType, err := strconv.ParseUint(fields[6], 10, 8)
	if err != nil {
		return nil, fmt.Errorf("invalid DS digest type: %w", err)
	}

	if !slices.Contains(ncasn.DS_DIGEST_TYPES, uint8(digestType)) {
		fmt.Println("unsupported DS digest type:", digestType)

		return nil, nil
	}

	bytes, err := hex.DecodeString(strings.ToLower(fields[7]))
	if err != nil {
		return nil, err
	}

	digest, err := util.ParseDsDigest(uint8(digestType), bytes)
	if err != nil {
		return nil, err
	}

	return &ncasn.RecordUnion{Ds: &ncasn.DS{
		KeyTag: uint16(keyTag),
		// Known to be valid if it reaches here.
		AlgorithmIndex: uint8(ncasn.GetKeyAlgorithmIndex(uint8(algorithm))), // nolint: gosec
		Digest:         *digest,
	}}, nil
}

func parseSshfp(fields []string) (*ncasn.RecordUnion, error) {
	keyAlgo, err := strconv.ParseUint(fields[0], 10, 3)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SSHFP key algo: %s", err.Error())
	}

	maxAlgo := 4
	if keyAlgo < uint64(maxAlgo) {
		fmt.Println("unsupported SSHFP key algo:", keyAlgo)

		return nil, nil
	}

	keyAlgo -= 4

	hashAlgo, err := strconv.ParseUint(fields[1], 10, 2)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SSHFP hash algo: %s", err.Error())
	}

	var sha256Id uint64 = 2
	if hashAlgo != sha256Id {
		fmt.Println("unsupported SSHFP hash algo:", hashAlgo)

		return nil, nil
	}

	bytes, err := hex.DecodeString(fields[2])
	if err != nil {
		return nil, err
	}

	length := len(bytes)

	if length != sha256.Size {
		return nil, fmt.Errorf("invalid SSHFP fingerprint length %d", length)
	}

	return &ncasn.RecordUnion{
		Sshfp: &ncasn.SSHFP{
			KeyAlgoIndex: uint8(keyAlgo),
			Fingerprint:  bytes,
		},
	}, nil
}

func parseTxt(fields []string, subdomain *string) *ncasn.RecordUnion {
	data := strings.Join(fields, " ")

	maxLen := 4096
	if len(data) > maxLen {
		return nil
	}

	var dnswl bool

	*subdomain, dnswl = strings.CutPrefix(*subdomain, "_token._dnswl")
	if dnswl {
		*subdomain = strings.TrimPrefix(*subdomain, ".")
	}

	return &ncasn.RecordUnion{Txt: &ncasn.TXT{
		Content: data,
		DnsWl:   dnswl,
	}}
}

func dsToJson(record *ncasn.RecordUnion, obj map[string]any) {
	ds, found := obj["ds"]

	var dsCast [][]any
	if found {
		// Exclusively set below.
		dsCast = ds.([][]any) // nolint: forcetypeassert
	}

	digestUnion := record.Ds.Digest

	var digest []byte

	switch {
	case digestUnion.Sha256 != nil:
		digest = *digestUnion.Sha256
	case digestUnion.Sha384 != nil:
		digest = *digestUnion.Sha384
	case digestUnion.Unassigned7 != nil:
		digest = *digestUnion.Unassigned7
	}

	obj["ds"] = append(dsCast,
		[]any{
			record.Ds.KeyTag,
			record.Ds.GetKeyAlgorithm(),
			digestUnion.GetType(),
			base64.StdEncoding.EncodeToString(digest),
		},
	)
}

func tlsaToJson(record *ncasn.RecordUnion, obj map[string]any) {
	tls, found := obj["tls"]

	var tlsCast [][]any
	if found {
		// Exclusively set below.
		tlsCast = tls.([][]any) // nolint: forcetypeassert
	}

	data := record.Tlsa.AssociationData

	var bytes []byte

	switch {
	case data.Sha256 != nil:
		bytes = *data.Sha256
	case data.Sha512 != nil:
		bytes = *data.Sha512
	case data.Unassigned0 != nil:
		bytes = *data.Unassigned0
	}

	var daneTa uint8 = 2

	obj["tls"] = append(tlsCast, []any{daneTa, record.Tlsa.Selector, data.GetMatchingType(), base64.StdEncoding.EncodeToString(bytes)})
}

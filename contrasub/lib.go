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

package contrasub

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"slices"

	"github.com/namecoin/go-asn/asn1"
	"github.com/namecoin/ncasn"
	"golang.org/x/crypto/blake2s"
)

func GetUniqueSubNames(records []ncasn.HiddenDomainRecord) int {
	subs := []string{}
	for _, record := range records {
		if !slices.Contains(subs, record.GetName()) {
			subs = append(subs, record.GetName())
		}
	}

	return len(subs)
}

func GetUniqueSubIndices(records []ncasn.HiddenDomainRecord) int {
	subs := []uint16{}
	for _, record := range records {
		if !slices.Contains(subs, *record.Index) {
			subs = append(subs, *record.Index)
		}
	}

	return len(subs)
}

func CalculateIndex(zone *ncasn.Zone, sub string) (*uint16, error) {
	if zone.Nonce == nil {
		return nil, errors.New("Not a hidden domain records zone")
	}

	return CalculateIndexWithCount(zone, sub, GetUniqueSubIndices(zone.Records.Hidden))
}

// Allows the caller to provide the number of unique subdomains to avoid redundantly calculating it in a loop
func CalculateIndexWithCount(zone *ncasn.Zone, sub string, count int) (*uint16, error) {
	if zone.Nonce == nil {
		return nil, errors.New("Not a hidden domain records zone")
	}

	subCount := big.NewInt(int64(count))

	concat := slices.Concat(zone.Nonce, []byte(sub))
	hash := blake2s.Sum256(concat)
	index := uint16(new(big.Int).Mod(new(big.Int).SetBytes(hash[:]), subCount).Uint64())
	return &index, nil
}

var maxSubsCache *int64

func getMaxSubs() (*int64, error) {
	// Reflection is expensive and this is static, so cache it
	if maxSubsCache != nil {
		return maxSubsCache, nil
	}

	typeFor := reflect.TypeFor[ncasn.HiddenDomainRecord]()
	field, ok := typeFor.FieldByName("Index")
	if !ok {
		return nil, errors.New("Index field not found")
	}

	tag := field.Tag.Get("asn1")
	opts, err := asn1.ParseTag(tag)
	if err != nil {
		return nil, err
	}

	if opts.SizeMax == nil {
		return nil, errors.New("opts.SizeMax == nil")
	}

	maxSubsCache = opts.SizeMax
	*maxSubsCache++
	return maxSubsCache, nil
}

func PreProcess(zone *ncasn.Zone) error {
	if zone.Records.Hidden == nil {
		return errors.New("Not a hidden domain records zone")
	}

	zone.Nonce = make([]byte, 8)
	subCount := GetUniqueSubNames(zone.Records.Hidden)
	maxSubs, err := getMaxSubs()
	if err != nil {
		return err
	}

	if int64(subCount) > *maxSubs {
		return fmt.Errorf("Subdomain count %d > %d", subCount, *maxSubs)
	}

	invalid := true
	for invalid {
		rand.Read(zone.Nonce)
		indices := []uint16{}
		mapped := map[string]uint16{}
		for i := range zone.Records.Hidden {
			sub := zone.Records.Hidden[i].GetName()
			existing, found := mapped[sub]
			if found {
				zone.Records.Hidden[i].Index = &existing
				continue
			}

			index, _ := CalculateIndexWithCount(zone, sub, subCount)
			if slices.Contains(indices, *index) {
				break
			}
			indices = append(indices, *index)
			mapped[sub] = *index
			zone.Records.Hidden[i].Index = index
		}

		invalid = len(indices) != subCount
	}

	return nil
}

// Calls PreProcess(&zone) immediately before ncasn.MarshalRecords(zone, encoding)
func MarshalRecords(zone ncasn.Zone, encoding ncasn.EncodingType) ([]byte, error) {
	if err := PreProcess(&zone); err != nil {
		return nil, err
	}

	return ncasn.MarshalRecords(zone, encoding)
}

func Lookup(zone *ncasn.Zone, sub string) ([]ncasn.HiddenDomainRecord, error) {
	idx, err := CalculateIndex(zone, sub)
	if err != nil {
		return nil, err
	}

	ret := []ncasn.HiddenDomainRecord{}

	for _, record := range zone.Records.Hidden {
		if *record.Index == *idx {
			ret = append(ret, record)
		}
	}

	return ret, nil
}

func NewHiddenDomainRecord(name string, data *ncasn.RecordUnion) ncasn.HiddenDomainRecord {
	ret := ncasn.HiddenDomainRecord{RecordData: *data}
	ret.SetName(name)
	return ret
}

// Adds the record to a zone that must not contain any visible domain records, and regenerates its indices
func AddRecord(zone *ncasn.Zone, record *ncasn.HiddenDomainRecord) error {
	if zone.Records.Visible != nil {
		return errors.New("Zone contains visible domain records")
	}

	zone.Records.Hidden = append(zone.Records.Hidden, *record)

	return PreProcess(zone)
}

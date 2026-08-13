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
	"reflect"
)

var DS_DIGEST_TYPES = []uint8{
	2, 4, 7, 8,
}

type DsDigestUnion struct {
	Sha256      *[]byte `asn1:"choice:0,size:32"`
	Sha384      *[]byte `asn1:"choice:1,size:48"`
	Unassigned7 *[]byte `asn1:"choice:2,size:32..64"`
	Unassigned8 *[]byte `asn1:"choice:3,size:32..64"`
}

func (digest *DsDigestUnion) GetType() uint8 {
	return DS_DIGEST_TYPES[GetChoice(reflect.ValueOf(digest).Elem())]
}

var DS_KEY_ALGOS = []uint8{
	15, 16, 18, 19,
}

func (record *DS) GetKeyAlgorithm() uint8 {
	return DS_KEY_ALGOS[record.AlgorithmIndex]
}

func GetKeyAlgorithmIndex(id uint8) int8 {
	for idx, algo := range DS_KEY_ALGOS {
		if algo == id {
			return int8(idx)
		}
	}

	return -1
}

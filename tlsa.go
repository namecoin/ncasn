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

import "reflect"

type TlsaUnion struct {
	Sha256      *[]byte `asn1:"choice:0,size:32"`
	Sha512      *[]byte `asn1:"choice:1,size:64"`
	Unassigned0 *[]byte `asn1:"choice:2,size:32..64"`
}

func (union *TlsaUnion) GetMatchingType() uint8 {
	return GetChoice(reflect.ValueOf(union).Elem()) + 1
}

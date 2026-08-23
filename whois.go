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

type WhoisFields struct {
	Registrant  *string `asn1:"ia5string,size:0..255"`
	Registrar   *string `asn1:"ia5string,size:0..255"`
	AdmContact  *string `asn1:"ia5string,size:0..255"`
	TechContact *string `asn1:"ia5string,size:0..255"`
}

type Whois struct {
	Fields *WhoisFields `asn1:"choice:0"`
	Entity *string      `asn1:"choice:1,ia5string,size:0..255"`
}

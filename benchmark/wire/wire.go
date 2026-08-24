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

package wire

import (
	"bytes"
	"encoding/binary"
	"slices"
	"strings"
	"unsafe"

	"github.com/miekg/dns"
	"github.com/sofia-nep/ncasn"
	"github.com/sofia-nep/ncasn/benchmark/util"
)

func domainToWire(domain string) []byte {
	labels := strings.Split(domain, ".")
	if len(labels[len(labels)-1]) != 0 {
		labels = append(labels, "")
	}

	ret := make([]byte, 0, len(domain))
	for _, label := range labels {
		length := byte(len(label))
		ret = append(ret, length)

		if length != 0 {
			ret = append(ret, []byte(label)...)
		}
	}

	return ret
}

// This also provides a binary representation of non-DNS records
func ToWire(record *ncasn.RecordUnion) []byte {
	switch {
	case record.A != nil:
		return record.A.Target
	case record.AAAA != nil:
		return record.AAAA.Bytes
	case record.Ds != nil:
		bytes := binary.BigEndian.AppendUint16(nil, record.Ds.KeyTag)
		bytes = append(bytes, record.Ds.GetKeyAlgorithm(), record.Ds.Digest.GetType())

		var digest []byte
		switch {
		case record.Ds.Digest.Sha256 != nil:
			digest = *record.Ds.Digest.Sha256
		case record.Ds.Digest.Sha384 != nil:
			digest = *record.Ds.Digest.Sha384
		case record.Ds.Digest.Unassigned7 != nil:
			digest = *record.Ds.Digest.Unassigned7
		case record.Ds.Digest.Unassigned8 != nil:
			digest = *record.Ds.Digest.Unassigned8
		}

		bytes = append(bytes, digest...)

		return bytes
	case record.Txt != nil:
		parts := util.SplitTxt(record.Txt.Content)

		var bytes []byte
		for _, part := range parts {
			bytes = append(bytes, byte(len(part)))
			bytes = append(bytes, part...)
		}

		return bytes
	case record.Tlsa != nil:
		dataUnion := record.Tlsa.AssociationData
		bytes := []byte{2, record.Tlsa.Selector, dataUnion.GetMatchingType()} // 2 = DANE-TA
		var data []byte
		switch {
		case dataUnion.Sha256 != nil:
			data = *dataUnion.Sha256
		case dataUnion.Sha512 != nil:
			data = *dataUnion.Sha512
		case dataUnion.Unassigned0 != nil:
			data = *dataUnion.Unassigned0
		case dataUnion.Unassigned1 != nil:
			data = *dataUnion.Unassigned1
		}

		return append(bytes, data...)
	case record.Loc != nil:
		size := record.Loc.Size
		if size == nil {
			size = &ncasn.LOCExponent{
				Mantissa: 1,
				Exp:      2,
			}
		}

		hp := record.Loc.HorizontalPrecision
		if hp == nil {
			hp = &ncasn.LOCExponent{
				Mantissa: 1,
				Exp:      6,
			}
		}

		vp := record.Loc.VerticalPrecision
		if vp == nil {
			vp = &ncasn.LOCExponent{
				Mantissa: 1,
				Exp:      3,
			}
		}

		sizeByte := size.Mantissa | (size.Exp << 4)
		hpByte := hp.Mantissa | (hp.Exp << 4)
		vpByte := vp.Mantissa | (hp.Exp << 4)

		// 0 = version
		bytes := []byte{0, sizeByte, hpByte, vpByte}
		bytes = binary.BigEndian.AppendUint32(bytes, record.Loc.Lat)
		bytes = binary.BigEndian.AppendUint32(bytes, record.Loc.Long)
		bytes = binary.BigEndian.AppendUint32(bytes, record.Loc.Altitude)

		return bytes
	case record.Sshfp != nil:
		// 2 = SHA-256
		bytes := []byte{record.Sshfp.GetKeyAlgo(), 2}
		return append(bytes, record.Sshfp.Fingerprint...)
	case record.Generic != nil:
		data := record.Generic.Target
		typeOf := record.Generic.Type
		if (typeOf == dns.TypeNS || typeOf == dns.TypeCNAME || typeOf == dns.TypeDNAME) && !strings.HasSuffix(data, ".") {
			data += "."
		}

		// Parsing the record contents alone is not possible...
		dummy := "example.org. 0 IN " + dns.TypeToString[record.Generic.Type] + " "
		parser := dns.NewZoneParser(bytes.NewReader([]byte(dummy+data)), "", "")
		rr, ok := parser.Next()

		if !ok {
			return nil
		}

		packed := make([]byte, 12+rr.Header().Rdlength)
		dns.PackRR(rr, packed, 0, nil, false)

		return packed[12:]
	case record.Alias != nil:
		return []byte(*record.Alias)
	case record.Onion != nil:
		return record.Onion.Bytes
	case record.I2p != nil:
		return record.I2p.Bytes
	case record.I2pLs2 != nil:
		data := record.I2pLs2
		secret := uint8(0)
		if data.Secret {
			secret = 1
		}

		clientAuth := uint8(0)
		if data.ClientAuth {
			clientAuth = 1
		}

		return slices.Concat([]byte{data.PublicSigType, data.BlindedSigType, secret, clientAuth}, data.Key)
	case record.Ipns != nil:
		return record.Ipns.Key
	case record.Hyphanet != nil:
		editionBits := unsafe.Pointer(&record.Hyphanet.Edition)
		data := slices.Concat(
			record.Hyphanet.KeyHash,
			record.Hyphanet.Key,
			record.Hyphanet.Extra,
			[]byte(record.Hyphanet.Name),
		)

		return binary.BigEndian.AppendUint64(data, *(*uint64)(editionBits))
	case record.Srv != nil:
		ret := binary.BigEndian.AppendUint16(nil, record.Srv.Priority)

		weight := uint16(0)
		if record.Srv.Weight != nil {
			weight = *record.Srv.Weight
		}
		ret = binary.BigEndian.AppendUint16(ret, weight)

		ret = binary.BigEndian.AppendUint16(ret, record.Srv.Port)

		return append(ret, domainToWire(record.Srv.Target)...)
	case record.Mx != nil:
		return append(binary.BigEndian.AppendUint16(nil, record.Mx.Priority), domainToWire(record.Mx.Target)...)
	}

	return nil
}

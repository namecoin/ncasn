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

type A struct {
	Target []byte `asn1:"size:4"`
}

// Use Bytes, the offset must be exported for go-asn to handle it but it is useless after processing.
type AAAA struct {
	ZeroOffset *uint8 `asn1:"optional,size:0..13"`
	Bytes      []byte `asn1:"size:0..16"`
}

type SRV struct {
	Priority uint16  `asn1:"size:0..65535"`
	Weight   *uint16 `asn1:"optional,size:0..65535"`
	Port     uint16  `asn1:"size:0..65535"`
	Target   string  `asn1:"ia5string,size:0..255"`
}

type DS struct {
	KeyTag uint16 `asn1:"size:0..65535"`
	// Use GetKeyAlgorithm().
	AlgorithmIndex uint8 `asn1:"size:0..3"`
	Digest         DsDigestUnion
}

type TXT struct {
	// May contain quoted strings up to 255 characters each.
	Content string `asn1:"ia5string,size:0..4096"`
}

// Always assumed to be DANE-TA
type TLSA struct {
	Selector        uint8 `asn1:"size:0..1"`
	AssociationData TlsaUnion
}

type CoordinateSecond struct {
	Numerator   uint8  `asn1:"size:0..63"`
	Denominator *uint8 `asn1:"optional,size:0..127"`
}

type LOC struct {
	DegreesLat  int8  `asn1:"size:-90..90"`
	DegreesLong int16 `asn1:"size:-180..180"`

	MinutesLat  *uint8 `asn1:"optional,size:0..60"`
	MinutesLong *uint8 `asn1:"optional,size:0..60"`

	SecondsLat  *CoordinateSecond `asn1:"optional"`
	SecondsLong *CoordinateSecond `asn1:"optional"`

	// Roughly from the bottom of the Kola Superdeep Borehole SG-3 to geosynchronous orbit, with the maximum increased so that the width of the interval is the next smallest power of 2.
	// If someone needs a wider interval than that, they surely have the budget to figure something out.
	Altitude int32 `asn1:"size:-12000..53535"`

	// From the spec, then rounded up to the next smallest power of 2.
	Size                *uint32 `asn1:"optional,size:0..134217727"`
	HorizontalPrecision *uint32 `asn1:"optional,size:0..134217727"`
	VerticalPrecision   *uint32 `asn1:"optional,size:0..134217727"`
}

type MX struct {
	Priority uint16 `asn1:"size:0..65535"`
	Target   string `asn1:"ia5string,size:0..255"`
}

type SSHFP struct {
	KeyAlgoIndex uint8 `asn1:"size:0..2"`
	// Assumed to be SHA-256.
	Fingerprint []byte `asn1:"size:32"`
}

func (record *SSHFP) GetKeyAlgo() uint8 {
	return record.KeyAlgoIndex + 4
}

type OnionV3 struct {
	// The version byte is omitted as upgrading may require a schema change anyway, append 0x03 before base32 encoding. The checksum bytes are also omitted.
	Bytes []byte `asn1:"size:32"`
}

type I2PB32 struct {
	Bytes []byte `asn1:"size:32"`
}

// https://i2p.net/en/docs/overview/naming/#extended-base32-names
type I2PEB32 struct {
	PublicSigType  uint8 `asn1:"size:0..31"` // "Don't expect 2-byte sigtypes to ever happen, we're only up to 13. No need to implement now."
	BlindedSigType uint8 `asn1:"size:0..31"`
	Secret         bool
	ClientAuth     bool
	Key            []byte `asn1:"size:32"` // More may be required for some SigTypes?
}

type HyphanetUSK struct {
	KeyHash []byte `asn1:"size:32"`
	Key     []byte `asn1:"size:32"`
	Extra   []byte `asn1:"size:5"`
	Name    string `asn1:"utf8string,size:1..512"`
	Edition int64  `asn1:"size:-9223372036854775808..9223372036854775807"`
}

type IPNS struct {
	// Assumed to be Ed25519.
	Key []byte `asn1:"size:32"`
}

type Generic struct {
	Type   uint16 `asn1:"size:0..65535"`
	Target string `asn1:"ia5string,size:0..255"`
}

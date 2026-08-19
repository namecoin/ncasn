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
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
)

type coordinate struct {
	Degrees int16
	Minutes *uint8
	Seconds *float64
	Offset  int
}

func parseCoordinate(fields []string, offset int) (*coordinate, error) {
	var pos string
	var neg string
	var max uint64
	if offset == 0 {
		pos = "N"
		neg = "S"
		max = 90
	} else {
		pos = "E"
		neg = "W"
		max = 180
	}

	deg, err := strconv.ParseUint(fields[offset], 10, 7)
	offset++
	if err != nil {
		return nil, fmt.Errorf("Invalid degrees: %s", err.Error())
	}

	if deg > max {
		return nil, fmt.Errorf("Invalid degrees: %d", deg)
	}

	var signedDeg *int16
	var mins *uint8
	switch fields[offset] {
	case pos:
		tmp := int16(deg)
		signedDeg = &tmp
	case neg:
		tmp := -int16(deg)
		signedDeg = &tmp
	default:
		tmp, err := strconv.ParseUint(fields[offset], 10, 6)
		if err != nil {
			return nil, fmt.Errorf("Invalid minutes: %s", err.Error())
		}

		if tmp > 60 {
			return nil, fmt.Errorf("Invalid minutes: %d", tmp)
		}

		tmp8 := uint8(tmp)
		mins = &tmp8
	}
	offset++

	var secs *float64
	if signedDeg == nil {
		switch fields[offset] {
		case pos:
			tmp := int16(deg)
			signedDeg = &tmp
		case neg:
			tmp := -int16(deg)
			signedDeg = &tmp
		default:
			tmp, err := strconv.ParseFloat(fields[offset], 64)
			if err != nil {
				return nil, fmt.Errorf("Invalid seconds: %s", err.Error())
			}

			if tmp < 0 || tmp > 59.999 {
				return nil, fmt.Errorf("Invalid seconds: %f", tmp)
			}

			secs = &tmp
		}
		offset++
	}

	if signedDeg == nil {
		switch fields[offset] {
		case pos:
			tmp := int16(deg)
			signedDeg = &tmp
		case neg:
			tmp := -int16(deg)
			signedDeg = &tmp
		default:
			return nil, fmt.Errorf("Invalid sign: %s", fields[offset])
		}
		offset++
	}

	return &coordinate{
		Degrees: *signedDeg,
		Minutes: mins,
		Seconds: secs,
		Offset:  offset,
	}, nil
}

var arcBaseline = uint32(math.Pow(2, 31))

// Formatted as in a zone file
func (record *LOC) String() string {
	latSign := "N"
	if record.Lat < arcBaseline {
		latSign = "S"
	}

	longSign := "E"
	if record.Long < arcBaseline {
		longSign = "W"
	}

	absLat := math.Abs(float64(record.Lat) - float64(arcBaseline))
	absLong := math.Abs(float64(record.Long) - float64(arcBaseline))

	degreesLat, rem := math.Modf(absLat / 3600000)
	minutesLat := uint8(rem * 60)
	secsLat := (rem - (float64(minutesLat) / 60)) * 3600

	degreesLong, rem := math.Modf(absLong / 3600000)
	minutesLong := uint8(rem * 60)
	secsLong := (rem - (float64(minutesLong) / 60)) * 3600

	alt := float64(record.Altitude/100) - 100000
	ret := fmt.Sprintf(
		"%d %d %.3f %s %d %d %.3f %s %.2fm",
		uint8(degreesLat), minutesLat, secsLat, latSign,
		uint8(degreesLong), minutesLong, secsLong, longSign,
		alt,
	)

	if record.Size == nil {
		return ret
	}
	ret += " " + strconv.Itoa(int(record.Size.Mantissa)*int(math.Pow10(int(record.Size.Exp))/100)) + ".00m"

	if record.HorizontalPrecision == nil {
		return ret
	}
	ret += " " + strconv.Itoa(int(record.HorizontalPrecision.Mantissa)*int(math.Pow10(int(record.HorizontalPrecision.Exp))/100)) + ".00m"

	if record.VerticalPrecision == nil {
		return ret
	}
	ret += " " + strconv.Itoa(int(record.VerticalPrecision.Mantissa)*int(math.Pow10(int(record.VerticalPrecision.Exp))/100)) + ".00m"

	return ret
}

func (coord *coordinate) toArcMillis() uint32 {
	secsFromDeg := float64(int64(coord.Degrees) * 3600)
	var secsFromMins float64
	if coord.Minutes != nil {
		if secsFromDeg > 0 {
			secsFromMins = float64(int64(*coord.Minutes) * 60)
		} else {
			secsFromMins = float64(-int64(*coord.Minutes) * 60)
		}
	}
	var secs float64
	if coord.Seconds != nil {
		if secsFromDeg > 0 {
			secs = *coord.Seconds
		} else {
			secs = -*coord.Seconds
		}
	}

	millis := (secsFromDeg + secsFromMins + secs) * 1000

	return uint32(int64(millis) + int64(arcBaseline))
}

func readExp(field string) (*LOCExponent, error) {
	field = strings.TrimSuffix(field, "m")
	value, err := strconv.ParseFloat(field, 64)
	if err != nil {
		return nil, err
	}

	value *= 100 // To centimeters

	if value > 9e9 {
		return nil, fmt.Errorf("Value too large: %f", value)
	}

	ret := LOCExponent{}
	ret.Exp = uint8(math.Log10(value))
	ret.Mantissa = uint8(value / math.Pow10(int(ret.Exp)))

	return &ret, nil
}

// Formatted as in a zone file
func StringToLoc(value string) (*LOC, error) {
	fields := strings.Fields(value)
	length := len(fields)

	if length < 5 {
		return nil, errors.New("Invalid LOC record")
	}

	latCoord, err := parseCoordinate(fields, 0)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse latitude: %s", err.Error())
	}

	longCoord, err := parseCoordinate(fields, latCoord.Offset)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse longitude: %s", err.Error())
	}

	ret := LOC{}

	ret.Lat = latCoord.toArcMillis()
	ret.Long = longCoord.toArcMillis()

	offset := longCoord.Offset
	if offset == length {
		return nil, errors.New("Missing altitude")
	}

	alt, err := strconv.ParseFloat(strings.TrimSuffix(fields[offset], "m"), 64)
	offset += 1
	if err != nil {
		return nil, fmt.Errorf("Failed to parse altitude: %s", err.Error())
	}

	if alt < -100000 || alt > math.MaxUint32-100000 {
		return nil, fmt.Errorf("Invalid altitude: %f", alt)
	}
	ret.Altitude = uint32(alt)*100 + 10000000

	if offset == length {
		return &ret, nil
	}
	ret.Size, err = readExp(fields[offset])
	offset += 1
	if err != nil {
		return nil, fmt.Errorf("Invalid size: %s", err.Error())
	}

	if offset == length {
		return &ret, nil
	}
	ret.HorizontalPrecision, err = readExp(fields[offset])
	offset += 1
	if err != nil {
		return nil, fmt.Errorf("Invalid horizontal precision: %s", err.Error())
	}

	if offset == length {
		return &ret, nil
	}
	ret.VerticalPrecision, err = readExp(fields[offset])
	if err != nil {
		return nil, fmt.Errorf("Invalid vertical precision: %s", err.Error())
	}

	return &ret, nil
}

type LOCExponent struct {
	Mantissa uint8 `asn1:"size:0..9"`
	Exp      uint8 `asn1:"size:0..9"`
}

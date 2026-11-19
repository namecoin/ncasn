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

type degree struct {
	Pos string
	Neg string
	Max int16
	Val int16
}

func parseDeg(fields []string, offset *int) (*degree, error) {
	ret := degree{}
	if *offset == 0 {
		ret.Pos = "N"
		ret.Neg = "S"
		ret.Max = 90
	} else {
		ret.Pos = "E"
		ret.Neg = "W"
		ret.Max = 180
	}

	tmp, err := strconv.ParseInt(fields[*offset], 10, 9)
	*offset++
	ret.Val = int16(tmp)

	if err != nil {
		return nil, errors.Join(ErrInvalidDegrees, err)
	}

	if ret.Val > ret.Max {
		return nil, fmt.Errorf("%w: %d", ErrInvalidDegrees, ret.Val)
	}

	return &ret, nil
}

type fractionUnit uint8

const (
	unitSign fractionUnit = iota
	unitMins
	unitSecs
)

func parseMinutes(field string) (*uint8, error) {
	tmp, err := strconv.ParseUint(field, 10, 6)
	if err != nil {
		return nil, errors.Join(ErrInvalidMinutes, err)
	}

	var maxMins uint64 = 60
	if tmp > maxMins {
		return nil, fmt.Errorf("%w: %d", ErrInvalidMinutes, tmp)
	}

	cast := uint8(tmp)

	return &cast, nil
}

func parseSeconds(field string) (*float64, error) {
	tmp, err := strconv.ParseFloat(field, 64)
	if err != nil {
		return nil, errors.Join(ErrInvalidSeconds, err)
	}

	if tmp < 0 || tmp > 59.999 {
		return nil, fmt.Errorf("%w: %f", ErrInvalidSeconds, tmp)
	}

	return &tmp, nil
}

func parseFraction(
	deg *degree,
	field string,
	out *coordinate,
	unit fractionUnit,
) (bool, error) {
	done := false

	var err error

	switch field {
	case deg.Pos:
		out.Degrees = deg.Val
		done = true
	case deg.Neg:
		out.Degrees = -deg.Val
		done = true
	default:
		switch unit {
		case unitMins:
			out.Minutes, err = parseMinutes(field)
		case unitSecs:
			out.Seconds, err = parseSeconds(field)
		case unitSign:
			err = fmt.Errorf("%w: %s", ErrInvalidSign, field)
		}
	}

	return done, err
}

func parseCoordinate(fields []string, offset int) (*coordinate, error) {
	deg, err := parseDeg(fields, &offset)
	if err != nil {
		return nil, err
	}

	var ret coordinate

	done, err := parseFraction(deg, fields[offset], &ret, unitMins)
	if err != nil {
		return nil, err
	}

	offset++

	if !done {
		done, err = parseFraction(deg, fields[offset], &ret, unitSecs)
		if err != nil {
			return nil, err
		}

		offset++
	}

	if !done {
		_, err = parseFraction(deg, fields[offset], &ret, unitSign)
		if err != nil {
			return nil, err
		}

		offset++
	}

	ret.Offset = offset

	return &ret, nil
}

var arcBase = 2.0
var arcExp = 31.0
var arcBaseline = uint32(math.Pow(arcBase, arcExp))
var cmInMeter uint32 = 100

// String formats the record as in a zone file.
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

	secsInDeg := 3600.0
	minsInDeg := 60.0
	mArcsecsInDeg := 3600000.0

	degreesLat, rem := math.Modf(absLat / mArcsecsInDeg)
	minutesLat := uint8(rem * minsInDeg)
	secsLat := (rem - (float64(minutesLat) / minsInDeg)) * secsInDeg

	degreesLong, rem := math.Modf(absLong / mArcsecsInDeg)
	minutesLong := uint8(rem * minsInDeg)
	secsLong := (rem - (float64(minutesLong) / minsInDeg)) * secsInDeg

	altOffset := 100000.0
	alt := float64(record.Altitude/cmInMeter) - altOffset
	ret := fmt.Sprintf(
		"%d %d %.3f %s %d %d %.3f %s %.2fm",
		uint8(degreesLat), minutesLat, secsLat, latSign,
		uint8(degreesLong), minutesLong, secsLong, longSign,
		alt,
	)

	expOffset := 100.0

	if record.Size == nil {
		return ret
	}

	ret += " " + strconv.Itoa(int(record.Size.Mantissa)*int(math.Pow10(int(record.Size.Exp))/expOffset)) + ".00m"

	if record.HorizontalPrecision == nil {
		return ret
	}

	ret += " " + strconv.Itoa(int(record.HorizontalPrecision.Mantissa)*int(math.Pow10(int(record.HorizontalPrecision.Exp))/expOffset)) + ".00m"

	if record.VerticalPrecision == nil {
		return ret
	}

	ret += " " + strconv.Itoa(int(record.VerticalPrecision.Mantissa)*int(math.Pow10(int(record.VerticalPrecision.Exp))/expOffset)) + ".00m"

	return ret
}

func (coord *coordinate) toArcMillis() (*uint32, error) {
	var secsInDeg int64 = 3600

	secsFromDeg := float64(int64(coord.Degrees) * secsInDeg)

	var secsInMin int64 = 60

	var secsFromMins float64

	if coord.Minutes != nil {
		secsFromMins = float64(int64(*coord.Minutes) * secsInMin)
		if secsFromDeg < 0 {
			secsFromMins = -secsFromMins
		}
	}

	var secs float64

	if coord.Seconds != nil {
		secs = *coord.Seconds
		if secsFromDeg < 0 {
			secs = -secs
		}
	}

	millisInSec := 1000.0
	millis := (secsFromDeg + secsFromMins + secs) * millisInSec

	val := millis + float64(arcBaseline)
	// Should never happen, but...
	if val < 0 || val > math.MaxUint32 {
		return nil, fmt.Errorf("%w: %f", ErrInvalidDegrees, val)
	}

	cast := uint32(val)

	return &cast, nil
}

func readExp(field string) (*LOCExponent, error) {
	field = strings.TrimSuffix(field, "m")

	value, err := strconv.ParseFloat(field, 64)
	if err != nil {
		return nil, err
	}

	value *= 100 // To centimeters.

	rfcMax := 9e9
	if value > rfcMax {
		return nil, fmt.Errorf("%w: %f", ErrValueTooLarge, value)
	}

	ret := LOCExponent{}
	ret.Exp = uint8(math.Log10(value))
	ret.Mantissa = uint8(value / math.Pow10(int(ret.Exp)))

	return &ret, nil
}

var ErrValueTooLarge = errors.New("value too large")
var ErrLocRecordTooShort = errors.New("invalid LOC record")
var ErrNoAltitude = errors.New("missing altitude")
var ErrInvalidAltitude = errors.New("invalid altitude")
var ErrInvalidMinutes = errors.New("invalid minutes")
var ErrInvalidSeconds = errors.New("invalid seconds")
var ErrInvalidDegrees = errors.New("invalid degrees")
var ErrInvalidSign = errors.New("invalid sign")
var ErrInvalidSize = errors.New("invalid size")
var ErrInvalidHorizontalPrecision = errors.New("invalid horizontal precision")
var ErrInvalidVerticalPrecision = errors.New("invalid vertical precision")
var ErrInvalidLatitude = errors.New("invalid latitude")
var ErrInvalidLongitude = errors.New("invalid longitude")

func parseOptionals(fields []string, offset int, out *LOC) error {
	var err error

	out.Size, err = readExp(fields[offset])
	offset += 1

	if err != nil {
		return errors.Join(ErrInvalidSize, err)
	}

	length := len(fields)
	if offset == length {
		return nil
	}

	out.HorizontalPrecision, err = readExp(fields[offset])
	offset += 1

	if err != nil {
		return errors.Join(ErrInvalidHorizontalPrecision, err)
	}

	if offset == length {
		return nil
	}

	out.VerticalPrecision, err = readExp(fields[offset])
	if err != nil {
		return errors.Join(ErrInvalidVerticalPrecision, err)
	}

	return nil
}

func parseCoordinates(fields []string) (*LOC, *int, error) {
	latCoord, err := parseCoordinate(fields, 0)
	if err != nil {
		return nil, nil, errors.Join(ErrInvalidLatitude, err)
	}

	longCoord, err := parseCoordinate(fields, latCoord.Offset)
	if err != nil {
		return nil, nil, errors.Join(ErrInvalidLongitude, err)
	}

	ret := LOC{}

	tmp, err := latCoord.toArcMillis()
	if err != nil {
		return nil, nil, err
	}

	ret.Lat = *tmp

	tmp, err = longCoord.toArcMillis()
	if err != nil {
		return nil, nil, err
	}

	ret.Long = *tmp

	offset := longCoord.Offset
	if offset == len(fields) {
		return nil, nil, ErrNoAltitude
	}

	return &ret, &offset, nil
}

// StringToLoc expects a string formatted as in a zone file.
func StringToLoc(value string) (*LOC, error) {
	fields := strings.Fields(value)
	length := len(fields)

	minValid := 5
	if length < minValid {
		return nil, ErrLocRecordTooShort
	}

	ret, offset, err := parseCoordinates(fields)
	if err != nil {
		return nil, err
	}

	alt, err := strconv.ParseFloat(strings.TrimSuffix(fields[*offset], "m"), 64)
	*offset += 1

	if err != nil {
		return nil, errors.Join(ErrInvalidAltitude, err)
	}

	if alt < -100000 || alt > math.MaxUint32-100000 {
		return nil, fmt.Errorf("%w: %f", ErrInvalidAltitude, alt)
	}

	var altOffset uint32 = 10000000

	ret.Altitude = uint32(alt)*cmInMeter + altOffset

	if *offset == length {
		return ret, nil
	}

	err = parseOptionals(fields, *offset, ret)
	if err != nil {
		return nil, err
	}

	return ret, nil
}

type LOCExponent struct {
	Mantissa uint8 `asn1:"size:0..9"`
	Exp      uint8 `asn1:"size:0..9"`
}

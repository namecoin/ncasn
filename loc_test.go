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

package ncasn_test

import (
	"testing"

	"github.com/sofia-nep/ncasn"
)

const LOC_DEFAULTS = "42 21 54 N 71 06 18 W -24m"

var convertedDefaults = ncasn.LOC{
	Lat:      2299997648,
	Long:     1891505648,
	Altitude: 9997600,
}

const LOC_COMPLETE = "42 21 43.952 N 71 5 6.344 W -24.00m 1.00m 200.00m 20.00m"

var convertedComplete = ncasn.LOC{
	Lat:      2299987600,
	Long:     1891577304,
	Altitude: 9997600,
	Size: &ncasn.LOCExponent{
		Mantissa: 1,
		Exp:      2,
	},
	HorizontalPrecision: &ncasn.LOCExponent{
		Mantissa: 2,
		Exp:      4,
	},
	VerticalPrecision: &ncasn.LOCExponent{
		Mantissa: 2,
		Exp:      3,
	},
}

const LOC_INVALID = "42 21 54 N 71 06 18 W"

func TestDefaultsToLoc(t *testing.T) {
	val, err := ncasn.StringToLoc(LOC_DEFAULTS)
	if err != nil {
		t.Fatalf("Failed with error: %s", err.Error())
	}

	if val.Lat != convertedDefaults.Lat {
		t.Errorf("Latitude != sample: %d != %d", val.Lat, convertedDefaults.Lat)
	}

	if val.Long != convertedDefaults.Long {
		t.Errorf("Longitude != sample: %d != %d", val.Long, convertedDefaults.Long)
	}

	if val.Altitude != convertedDefaults.Altitude {
		t.Errorf("Altitude != sample: %d != %d", val.Altitude, convertedDefaults.Altitude)
	}

	if val.Size != nil {
		t.Error("Size is not nil")
	}

	if val.HorizontalPrecision != nil {
		t.Error("Horizontal precision is not nil")
	}

	if val.VerticalPrecision != nil {
		t.Error("Vertical precision is not nil")
	}
}

func TestCompleteToLoc(t *testing.T) {
	val, err := ncasn.StringToLoc(LOC_COMPLETE)
	if err != nil {
		t.Fatalf("Failed with error: %s", err.Error())
	}

	if val.Lat != convertedComplete.Lat {
		t.Errorf("Latitude != sample: %d != %d", val.Lat, convertedComplete.Lat)
	}

	if val.Long != convertedComplete.Long {
		t.Errorf("Longitude != sample: %d != %d", val.Long, convertedComplete.Long)
	}

	if val.Altitude != convertedComplete.Altitude {
		t.Errorf("Altitude != sample: %d != %d", val.Altitude, convertedComplete.Altitude)
	}

	if val.Size == nil {
		t.Fatal("Size is nil")
	}

	if val.Size.Mantissa != convertedComplete.Size.Mantissa {
		t.Errorf("Size mantissa != sample: %d != %d", val.Size.Mantissa, convertedComplete.Size.Mantissa)
	}

	if val.Size.Exp != convertedComplete.Size.Exp {
		t.Errorf("Size exponent != sample: %d != %d", val.Size.Exp, convertedComplete.Size.Exp)
	}

	if val.HorizontalPrecision == nil {
		t.Fatal("Horizontal precision is nil")
	}

	if val.HorizontalPrecision.Mantissa != convertedComplete.HorizontalPrecision.Mantissa {
		t.Errorf("Horizontal precision mantissa != sample: %d != %d", val.HorizontalPrecision.Mantissa, convertedComplete.HorizontalPrecision.Mantissa)
	}

	if val.HorizontalPrecision.Exp != convertedComplete.HorizontalPrecision.Exp {
		t.Errorf("Horizontal precision exponent != sample: %d != %d", val.HorizontalPrecision.Exp, convertedComplete.HorizontalPrecision.Exp)
	}

	if val.VerticalPrecision == nil {
		t.Fatal("Vertical precision is nil")
	}

	if val.VerticalPrecision.Mantissa != convertedComplete.VerticalPrecision.Mantissa {
		t.Errorf("Vertical precision mantissa != sample: %d != %d", val.VerticalPrecision.Mantissa, convertedComplete.VerticalPrecision.Mantissa)
	}

	if val.VerticalPrecision.Exp != convertedComplete.VerticalPrecision.Exp {
		t.Errorf("Vertical precision exponent != sample: %d != %d", val.VerticalPrecision.Exp, convertedComplete.VerticalPrecision.Exp)
	}
}

func TestCompleteFromLoc(t *testing.T) {
	val := convertedComplete.String()
	if val != LOC_COMPLETE {
		t.Errorf("String != sample: %s != %s", val, LOC_COMPLETE)
	}
}

func TestInvalidToLoc(t *testing.T) {
	_, err := ncasn.StringToLoc(LOC_INVALID)
	if err == nil {
		t.Error("Should have errored")
	}
}

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

package main

import (
	"flag"
	"strconv"
	"testing"

	"github.com/namecoin/ncasn"
	"github.com/namecoin/ncasn/contrasub"
)

var domainCount = flag.Int("count", -1, "Number of subdomains to use in the benchmark")

func Benchmark_time(b *testing.B) {
	var records []ncasn.HiddenDomainRecord

	for i := 0; i < *domainCount; i++ {
		record := ncasn.HiddenDomainRecord{
			RecordData: ncasn.RecordUnion{
				A: &ncasn.A{
					Target: []byte{0, 0, 0, byte(i)},
				},
			},
		}
		record.SetName(strconv.Itoa(i))
		records = append(records, record)
	}

	zone := ncasn.Zone{Records: ncasn.RecordsUnion{Hidden: records}}

	for b.Loop() {
		err := contrasub.PreProcess(&zone, false, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}

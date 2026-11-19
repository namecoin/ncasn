# An ASN.1-based encoding library for Namecoin data

## Usage

An `ncasn.Zone` object represents a single name in the d/ namespace, containing a slice of `ncasn.Record`s as well as WHOIS data. Zones can then be serialized into ASN.1 UPER, APER, or a custom mixed radix encoding through `ncasn.MarshalRecords()`. For encoding efficiency, some records make some reasonable assumptions (mainly involving restricting certain insecure record data), which are documented through comments.

## Efficiency

Storage usage was benchmarked against proposed [Tor CAA](https://spec.torproject.org/proposals/343-rend-caa.html) and [IETF CBOR DNS](https://datatracker.ietf.org/doc/draft-lenders-dns-cbor) standards as well as [the JSON-based Namecoin format](https://github.com/namecoin/proposals), based on a sample of private DNS zones and (in much larger numbers) the Namecoin blockchain, the blockchain dumping and benchmarking code can be found in the `benchmark` module.

### Caveats

Some (hopefully reasonable) assumptions had to be made in order to achieve good coverage of the data, specifically, some record types had to be encoded in unspecified ways in some formats. For example, IPNS records are encoded as the raw key bytes in CBOR, and textual representations were used in the Tor format. Some record types were still excluded entirely (e.g., Namecoin `import`s), but did not meaningfully affect the results (see below). Additionally, [1 byte is added to the length calculation of our data when comparing it to JSON/CBOR](https://github.com/namecoin/ncasn/issues/4), but not when comparing it to the Tor format.

### Results

These numbers are subject to change (hopefully improve!) as the format is updated and the benchmark may have to be tweaked, but the following comparisons to different formats can currently be made (as a ratio with our storage usage as the denominator):

Blockchain data were obtained with a minimum block height of 0 and maximum of 840795. Zone/blockchain coverage ratios refer to the exclusion of records based on the aforementioned assumptions.

Benchmarks were performed with the sample of DNS zones as-is, as well as with certain Namecoin-irrelevant records (e.g., DKIM data) elided to reduce the number of subdomains.

Without elision:  
Standard benchmark results:
```
Zone file coverage: 0.29
Blockchain coverage: 1.00

APER benchmark results:
Format: Size ratio | Record coverage | Record count
JSON: 4.18207 | 1.00 | 201038
Tor: 1.89430 | 0.87 | 174567
CBOR: 1.48155 | 1.00 | 201036

UPER benchmark results:
Format: Size ratio | Record coverage | Record count
JSON: 4.31502 | 1.00 | 201038
Tor: 1.97200 | 0.87 | 174567
CBOR: 1.52774 | 1.00 | 201036
APER: 1.02907 | 1.00 | 201038

Mixed radix benchmark results:
Format: Size ratio | Record coverage | Record count
JSON: 4.89152 | 1.00 | 201038
Tor: 2.20158 | 0.87 | 174567
CBOR: 1.74913 | 1.00 | 201036
APER: 1.21086 | 1.00 | 201038
UPER: 1.17665 | 1.00 | 201038
```
Results with contrasub (note the caveats in runHiddenComparison()):
```
Zone file coverage: 0.29
Blockchain coverage: 1.00

APER benchmark results:
Format: Size ratio | Record coverage | Record count
JSON: 3.88018 | 1.00 | 200719
Tor: 1.73474 | 0.87 | 174248
CBOR: 1.43079 | 1.00 | 200717

UPER benchmark results:
Format: Size ratio | Record coverage | Record count
JSON: 3.99356 | 1.00 | 200719
Tor: 1.81458 | 0.87 | 174248
CBOR: 1.48659 | 1.00 | 200717
APER: 1.03456 | 1.00 | 200719

Mixed radix benchmark results:
Format: Size ratio | Record coverage | Record count
JSON: 4.51971 | 1.00 | 200719
Tor: 2.02309 | 0.87 | 174248
CBOR: 1.68787 | 1.00 | 200717
APER: 1.19654 | 1.00 | 200719
UPER: 1.15656 | 1.00 | 200719
```
With elision:  
Standard benchmark results:
```
Zone file coverage: 0.87
Blockchain coverage: 1.00

APER benchmark results:
Format: Size ratio | Record coverage | Record count
JSON: 4.18334 | 1.00 | 200955
Tor: 1.89473 | 0.87 | 174484
CBOR: 1.48164 | 1.00 | 200953

UPER benchmark results:
Format: Size ratio | Record coverage | Record count
JSON: 4.31636 | 1.00 | 200955
Tor: 1.97247 | 0.87 | 174484
CBOR: 1.52786 | 1.00 | 200953
APER: 1.02916 | 1.00 | 200955

Mixed radix benchmark results:
Format: Size ratio | Record coverage | Record count
JSON: 4.89306 | 1.00 | 200955
Tor: 2.20213 | 0.87 | 174484
CBOR: 1.74929 | 1.00 | 200953
APER: 1.21132 | 1.00 | 200955
UPER: 1.17700 | 1.00 | 200955
```
Results with contrasub (note the caveats in runHiddenComparison()):
```
Zone file coverage: 0.87
Blockchain coverage: 1.00

APER benchmark results:
Format: Size ratio | Record coverage | Record count
JSON: 3.87991 | 1.00 | 200722
Tor: 1.73449 | 0.87 | 174251
CBOR: 1.43043 | 1.00 | 200720

UPER benchmark results:
Format: Size ratio | Record coverage | Record count
JSON: 3.99331 | 1.00 | 200722
Tor: 1.81434 | 0.87 | 174251
CBOR: 1.48623 | 1.00 | 200720
APER: 1.03460 | 1.00 | 200722

Mixed radix benchmark results:
Format: Size ratio | Record coverage | Record count
JSON: 4.51942 | 1.00 | 200722
Tor: 2.02281 | 0.87 | 174251
CBOR: 1.68747 | 1.00 | 200720
APER: 1.19663 | 1.00 | 200722
UPER: 1.15661 | 1.00 | 200722
```

Results binned based on the record types in a given zone are available in doc/binned.

Contrasub time complexity benchmark results (`cd benchmark && go test -bench=. -benchtime=300x -args -count=20`):
```
goos: linux
goarch: amd64
pkg: github.com/namecoin/ncasn/benchmark
cpu: 11th Gen Intel(R) Core(TM) i5-11400H @ 2.70GHz
Benchmark_time-12            300        13932216914 ns/op
PASS
ok      github.com/namecoin/ncasn/benchmark     4179.694s
```

Contrasub results are heavily affected by whether record data are deduplicated by deliberately grinding for index collisions (by roughly 50pp), the results above do not utilize that feature due to the added time complexity.

## Copyright

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

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
JSON: 4.18175 | 1.00 | 201038
Tor: 1.89430 | 0.87 | 174567
CBOR: 1.48108 | 1.00 | 201038

UPER benchmark results:
Format: Size ratio | Record coverage | Record count
JSON: 4.31470 | 1.00 | 201038
Tor: 1.97200 | 0.87 | 174567
CBOR: 1.52726 | 1.00 | 201038
APER: 1.02907 | 1.00 | 201038

Mixed radix benchmark results:
Format: Size ratio | Record coverage | Record count
JSON: 4.89117 | 1.00 | 201038
Tor: 2.20158 | 0.87 | 174567
CBOR: 1.74862 | 1.00 | 201038
APER: 1.21086 | 1.00 | 201038
UPER: 1.17665 | 1.00 | 201038
```
Results with contrasub (note the caveats in runHiddenComparison()):
```
Zone file coverage: 0.29
Blockchain coverage: 1.00

APER benchmark results:
Format: Size ratio | Record coverage | Record count
JSON: 4.47388 | 1.00 | 200719
Tor: 2.04898 | 0.87 | 174248
CBOR: 1.62922 | 1.00 | 200719

UPER benchmark results:
Format: Size ratio | Record coverage | Record count
JSON: 4.56341 | 1.00 | 200719
Tor: 2.13418 | 0.87 | 174248
CBOR: 1.68780 | 1.00 | 200719
APER: 1.02407 | 1.00 | 200719

Mixed radix benchmark results:
Format: Size ratio | Record coverage | Record count
JSON: 5.11138 | 1.00 | 200719
Tor: 2.35423 | 0.87 | 174248
CBOR: 1.89750 | 1.00 | 200719
APER: 1.20012 | 1.00 | 200719
UPER: 1.17191 | 1.00 | 200719
```
With elision:  
Standard benchmark results:
```
Zone file coverage: 0.87
Blockchain coverage: 1.00

APER benchmark results:
Format: Size ratio | Record coverage | Record count
JSON: 4.18294 | 1.00 | 200955
Tor: 1.89473 | 0.87 | 174484
CBOR: 1.48111 | 1.00 | 200955

UPER benchmark results:
Format: Size ratio | Record coverage | Record count
JSON: 4.31595 | 1.00 | 200955
Tor: 1.97247 | 0.87 | 174484
CBOR: 1.52731 | 1.00 | 200955
APER: 1.02916 | 1.00 | 200955

Mixed radix benchmark results:
Format: Size ratio | Record coverage | Record count
JSON: 4.89262 | 1.00 | 200955
Tor: 2.20213 | 0.87 | 174484
CBOR: 1.74872 | 1.00 | 200955
APER: 1.21132 | 1.00 | 200955
UPER: 1.17700 | 1.00 | 200955
```
Results with contrasub (note the caveats in runHiddenComparison()):
```
Zone file coverage: 0.87
Blockchain coverage: 1.00

APER benchmark results:
Format: Size ratio | Record coverage | Record count
JSON: 4.47334 | 1.00 | 200722
Tor: 2.04838 | 0.87 | 174251
CBOR: 1.62851 | 1.00 | 200722

UPER benchmark results:
Format: Size ratio | Record coverage | Record count
JSON: 4.56286 | 1.00 | 200722
Tor: 2.13359 | 0.87 | 174251
CBOR: 1.68712 | 1.00 | 200722
APER: 1.02409 | 1.00 | 200722

Mixed radix benchmark results:
Format: Size ratio | Record coverage | Record count
JSON: 5.11081 | 1.00 | 200722
Tor: 2.35366 | 0.87 | 174251
CBOR: 1.89682 | 1.00 | 200722
APER: 1.20022 | 1.00 | 200722
UPER: 1.17198 | 1.00 | 200722
```

Results binned based on the record types in a given zone are available in doc/binned/Visible.txt and doc/binned/Hidden.txt.

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
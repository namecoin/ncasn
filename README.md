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
Standard benchmark results:
```
Zone file coverage: 0.29
Blockchain coverage: 1.00

APER benchmark results:
Format: Size ratio | Record coverage | Record count
JSON: 4.18719 | 1.00 | 200890
Tor: 1.89511 | 0.87 | 174419
CBOR: 1.48220 | 1.00 | 200890

UPER benchmark results:
Format: Size ratio | Record coverage | Record count
JSON: 4.32033 | 1.00 | 200890
Tor: 1.97290 | 0.87 | 174419
CBOR: 1.52843 | 1.00 | 200890
APER: 1.02916 | 1.00 | 200890

Mixed radix benchmark results:
Format: Size ratio | Record coverage | Record count
JSON: 4.89763 | 1.00 | 200890
Tor: 2.20271 | 0.87 | 174419
CBOR: 1.75001 | 1.00 | 200890
APER: 1.21167 | 1.00 | 200890
UPER: 1.17734 | 1.00 | 200890
```
Results with contrasub (note the caveats in runHiddenComparison()):
```
Zone file coverage: 0.29
Blockchain coverage: 1.00

APER benchmark results:
Format: Size ratio | Record coverage | Record count
JSON: 3.76798 | 1.00 | 200630
Tor: 1.64241 | 0.87 | 174159
CBOR: 1.34714 | 1.00 | 200630

UPER benchmark results:
Format: Size ratio | Record coverage | Record count
JSON: 3.87222 | 1.00 | 200630
Tor: 1.71996 | 0.87 | 174159
CBOR: 1.39438 | 1.00 | 200630
APER: 1.03467 | 1.00 | 200630

Mixed radix benchmark results:
Format: Size ratio | Record coverage | Record count
JSON: 4.39768 | 1.00 | 200630
Tor: 1.91431 | 0.87 | 174159
CBOR: 1.59666 | 1.00 | 200630
APER: 1.19696 | 1.00 | 200630
UPER: 1.15685 | 1.00 | 200630
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
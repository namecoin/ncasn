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
```
Zone file coverage: 0.29
Blockchain coverage: 1.00

APER benchmark results:
Format: Size ratio | Record coverage | Record count
JSON: 4.19522 | 1.00 | 200883
Tor: 1.90205 | 0.87 | 174412
CBOR: 1.48887 | 1.00 | 200883

UPER benchmark results:
Format: Size ratio | Record coverage | Record count
JSON: 4.33340 | 1.00 | 200883
Tor: 1.98505 | 0.87 | 174412
CBOR: 1.53709 | 1.00 | 200883
APER: 0.97422 | 1.00 | 200883

Mixed radix benchmark results:
Format: Size ratio | Record coverage | Record count
JSON: 4.93907 | 1.00 | 200883
Tor: 2.23178 | 0.87 | 174412
CBOR: 1.76511 | 1.00 | 200883
APER: 0.82470 | 1.00 | 200883
UPER: 0.84652 | 1.00 | 200883
```

Results binned based on the record types in a given zone are available in Binned.txt.
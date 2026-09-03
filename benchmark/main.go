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

package main

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"

	"github.com/namecoin/ncasn"
	"github.com/namecoin/ncasn/benchmark/blockchain"
	"github.com/namecoin/ncasn/benchmark/util"
	"github.com/namecoin/ncasn/benchmark/zone"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "No operation was provided")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "collect-nmc":
		err := collectNmc()
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		}
	case "run":
		benchmark()
	default:
		fmt.Fprintln(os.Stderr, "Invalid operation")
		os.Exit(1)
	}
}

func collectNmc() error {
	argLen := len(os.Args)
	if argLen < 4 {
		return errors.New("Not enough arguments")
	}

	cookie, err := blockchain.GetCookie()
	if err != nil {
		return err
	}

	output, err := os.OpenFile(os.Args[3], os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0664)
	if err != nil {
		return err
	}
	defer output.Close()
	_, err = output.WriteString("[")
	if err != nil {
		return err
	}

	var next *string
	for {
		var minHeight *uint64
		var maxHeight *uint64
		if argLen > 4 {
			tmpMin, err := strconv.ParseUint(os.Args[4], 10, 64)
			if err != nil {
				return fmt.Errorf("Invalid min height: %s", err.Error())
			}
			minHeight = &tmpMin

			if argLen > 5 {
				tmpMax, err := strconv.ParseUint(os.Args[5], 10, 64)
				if err != nil {
					return fmt.Errorf("Invalid max height: %s", err.Error())
				}
				maxHeight = &tmpMax
			}
		}

		body, err := blockchain.ScanNames(next, *cookie)
		if err != nil {
			return err
		}

		next, err = blockchain.ProcessBody(body, output, *cookie, next == nil, minHeight, maxHeight)
		if err != nil {
			return err
		}

		if next == nil {
			break
		}
	}

	// Remove last comma
	curr, err := output.Seek(0, 1)
	if err != nil {
		return err
	}
	if curr != 1 {
		_, err = output.Seek(-1, 1)
		if err != nil {
			return err
		}
	}

	_, err = output.WriteString("]")

	return err
}

type Result struct {
	Ratio    float64
	Coverage float64
	Count    int
}

type Results struct {
	Json *Result
	Cbor *Result
	Tor  *Result
}

func runComparison(zone *util.Zone) (*Results, error) {
	cborCopy := []ncasn.Record{}
	torCopy := []ncasn.Record{}
	for i := range zone.Zone.Records {
		if !slices.Contains(zone.Cbor.Ignored, &zone.Zone.Records[i]) {
			cborCopy = append(cborCopy, zone.Zone.Records[i])
		}

		if !slices.Contains(zone.Tor.Ignored, &zone.Zone.Records[i]) {
			torCopy = append(torCopy, zone.Zone.Records[i])
		}
	}

	cborZone := ncasn.Zone{
		Records: cborCopy,
	}

	torZone := ncasn.Zone{
		Records: torCopy,
	}

	total := len(zone.Zone.Records)

	jsonUper, err := ncasn.MarshalRecords(*zone.Zone)
	if err != nil {
		return nil, err
	}

	jsonResult := Result{
		// + 1 to account for an extra byte used for schema versioning, see #4
		Ratio: float64(len(zone.Json)) / float64(len(jsonUper)+1),
		Count: total,
	}

	// Dummy for empty zones
	cborResult := Result{
		Ratio: 1.0,
		Count: 0,
	}
	torResult := cborResult

	if len(cborCopy) != 0 {
		cborUper, err := ncasn.MarshalRecords(cborZone)
		if err != nil {
			return nil, err
		}

		cborResult = Result{
			// + 1 to account for an extra byte used for schema versioning, see #4
			Ratio: float64(len(zone.Cbor.Data)) / float64(len(cborUper)+1),
			Count: len(cborCopy),
		}
	}

	if len(torCopy) != 0 {
		torUper, err := ncasn.MarshalRecords(torZone)
		if err != nil {
			return nil, err
		}

		torSum := 0
		for _, torRec := range zone.Tor.Data {
			torSum += len(torRec)
		}

		torResult = Result{
			Ratio: float64(torSum) / float64(len(torUper)),
			Count: len(torCopy),
		}
	}

	return &Results{
		Json: &jsonResult,
		Cbor: &cborResult,
		Tor:  &torResult,
	}, nil
}

func weightedAverage(results []Results) Results {
	var jsonResult Result
	var torResult Result
	var cborResult Result

	for _, result := range results {
		jsonCount := float64(result.Json.Count)
		jsonResult.Ratio += result.Json.Ratio * jsonCount
		jsonResult.Count += result.Json.Count

		torCount := float64(result.Tor.Count)
		torResult.Ratio += result.Tor.Ratio * torCount
		torResult.Count += result.Tor.Count

		cborCount := float64(result.Cbor.Count)
		cborResult.Ratio += result.Cbor.Ratio * cborCount
		cborResult.Count += result.Cbor.Count
	}

	jsonCount := float64(jsonResult.Count)
	jsonResult.Ratio /= jsonCount
	jsonResult.Coverage = 1.0

	torCount := float64(torResult.Count)
	torResult.Ratio /= torCount
	torResult.Coverage = torCount / jsonCount

	cborCount := float64(cborResult.Count)
	cborResult.Ratio /= cborCount
	cborResult.Coverage = cborCount / jsonCount

	return Results{Json: &jsonResult, Tor: &torResult, Cbor: &cborResult}
}

func benchmark() {
	if len(os.Args) < 4 {
		fmt.Fprintln(os.Stderr, "Insufficient arguments")
		os.Exit(1)
	}

	zones, err := zone.ReadZones(os.Args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	fromChain, err := blockchain.JsonFileToUper(os.Args[3])
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	aggregated := append(zones, fromChain...)

	var results []Results
	for _, zone := range aggregated {
		result, err := runComparison(&zone)
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		}

		results = append(results, *result)
	}

	final := weightedAverage(results)

	fmt.Println("Benchmark results:")
	fmt.Println("Format: Size ratio | Record coverage | Record count")
	fmt.Printf("JSON: %.2f | %.2f | %d\n", final.Json.Ratio, final.Json.Coverage, final.Json.Count)
	fmt.Printf("Tor: %.2f | %.2f | %d\n", final.Tor.Ratio, final.Tor.Coverage, final.Tor.Count)
	fmt.Printf("CBOR: %.2f | %.2f | %d\n", final.Cbor.Ratio, final.Cbor.Coverage, final.Cbor.Count)
}

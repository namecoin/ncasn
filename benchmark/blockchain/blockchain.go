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

package blockchain

import (
	"bytes"
	"cmp"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"

	"github.com/google/uuid"
)

type Name struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Response struct {
	Result []Name `json:"result"`
}

type Request struct {
	Jsonrpc string `json:"jsonrpc"`
	Id      string `json:"id"`
	Method  string `json:"method"`
	Params  []any  `json:"params"`
}

func createRequest(method string, params []any, version string) Request {
	return Request{
		Jsonrpc: version,
		Id:      uuid.NewString(),
		Method:  method,
		Params:  params,
	}
}

func runHttp(rpcMethod string, params []any, cookie string, version string) ([]byte, error) {
	obj, err := json.Marshal(createRequest(rpcMethod, params, version))
	if err != nil {
		return nil, err
	}

	reader := bytes.NewReader(obj)

	req, err := http.NewRequest("POST", "http://"+os.Args[2], reader)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(cookie)))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("Non 200 status code for %s: %d", rpcMethod, resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

func ScanNames(prev *string, cookie string) ([]byte, error) {
	params := []any{prev, 1000, map[string]string{"prefix": "d/"}}

	return runHttp("name_scan", params, cookie, "1.0")
}

func expandNames(names []Name, cookie string) ([]Name, error) {
	copy := make([]Name, 0, len(names))
	for _, name := range names {
		body, err := runHttp("name_history", []any{name.Name}, cookie, "2.0")
		if err != nil {
			return nil, err
		}

		var resp Response
		err = json.Unmarshal(body, &resp)
		if err != nil {
			return nil, err
		}

		// Deduplicate values
		slices.SortFunc(resp.Result, func(a Name, b Name) int { return cmp.Compare(a.Value, b.Value) })
		dedup := slices.Compact(resp.Result)

		copy = append(copy, dedup...)
	}

	return copy, nil
}

func ProcessBody(body []byte, out *os.File, cookie string, first bool) (*string, error) {
	var response Response
	err := json.Unmarshal(body, &response)
	if err != nil {
		return nil, err
	}

	response.Result = slices.DeleteFunc(response.Result, func(name Name) bool {
		return len(name.Name) == 0
	})

	if len(response.Result) <= 1 {
		return nil, nil
	}

	if !first {
		// Remove the name used as the offset
		response.Result = response.Result[1:]
	}

	last := &response.Result[len(response.Result)-1].Name

	expanded, err := expandNames(response.Result, cookie)
	if err != nil {
		return nil, err
	}

	for _, name := range expanded {
		bytes, err := json.Marshal(name)
		if err != nil {
			return nil, err
		}

		_, err = out.Write(bytes)
		if err != nil {
			return nil, err
		}

		_, err = out.WriteString(",")
		if err != nil {
			return nil, err
		}
	}

	return last, nil
}

func GetCookie() (*string, error) {
	home, found := os.LookupEnv("HOME")
	if !found {
		return nil, errors.New("No $HOME to look for cookie file")
	}

	cookieFd, err := os.Open(home + "/.namecoin/.cookie")
	if err != nil {
		return nil, err
	}
	defer cookieFd.Close()

	cookie, err := io.ReadAll(cookieFd)
	if err != nil {
		return nil, err
	}
	str := string(cookie)

	return &str, nil
}

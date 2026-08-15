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
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

var HYPHA_ENCODING = base64.NewEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789~-").WithPadding(base64.NoPadding)

func (record *HyphanetUSK) ToKey() string {
	return fmt.Sprintf(
		"USK@%s,%s,%s/%s/%d/",
		HYPHA_ENCODING.EncodeToString(record.KeyHash),
		HYPHA_ENCODING.EncodeToString(record.Key),
		HYPHA_ENCODING.EncodeToString(record.Extra),
		record.Name,
		record.Edition,
	)
}

func USKRecordFromKey(key string) (*HyphanetUSK, error) {
	key, found := strings.CutPrefix(key, "USK@")
	if !found {
		return nil, errors.New("Hyphanet key must be a USK.")
	}

	slashSeparated := strings.Split(key, "/")

	// Trailing slash
	if len(slashSeparated) != 4 {
		return nil, errors.New("Hyphanet key must have 3 slash-separated sections.")
	}

	commaSeparated := strings.Split(slashSeparated[0], ",")
	if len(commaSeparated) != 3 {
		return nil, errors.New("Hyphanet key must have 3 comma-separated sections.")
	}

	hash := commaSeparated[0]
	keyData := commaSeparated[1]
	extra := commaSeparated[2]

	name := slashSeparated[1]
	edition := slashSeparated[2]

	rawHash, err := HYPHA_ENCODING.DecodeString(hash)
	if err != nil {
		return nil, err
	}

	rawKey, err := HYPHA_ENCODING.DecodeString(keyData)
	if err != nil {
		return nil, err
	}

	rawExtra, err := HYPHA_ENCODING.DecodeString(extra)
	if err != nil {
		return nil, err
	}

	editionNum, err := strconv.ParseInt(edition, 10, 64)
	if err != nil {
		return nil, err
	}

	return &HyphanetUSK{
		KeyHash: rawHash,
		Key:     rawKey,
		Extra:   rawExtra,
		Name:    name,
		Edition: editionNum,
	}, nil
}

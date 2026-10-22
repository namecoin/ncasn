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

package ncasn_test

import (
	"testing"

	"github.com/namecoin/ncasn"
)

func SrvNameToMeta_test(t *testing.T) {
	name := "_sipfederationtls._tcp"
	t.Run(name, func(t *testing.T) {
		res := ncasn.SrvNameToMeta(name)
		if res == nil {
			t.Fatal("res == nil")
		}

		if res.Service != ncasn.SipFederationTls {
			t.Error("Wrong service")
		}

		if res.Proto != ncasn.Tcp {
			t.Error("Wrong proto")
		}
	})

	name = "_http._tls"
	t.Run(name, func(t *testing.T) {
		res := ncasn.SrvNameToMeta(name)
		if res == nil {
			t.Fatal("res == nil")
		}

		if res.Service != ncasn.Http {
			t.Error("Wrong service")
		}

		if res.Proto != ncasn.Tls {
			t.Error("Wrong proto")
		}
	})
}

func SrvToPrefix_test(t *testing.T) {
	meta := ncasn.SRVMeta{
		Service: ncasn.Http,
		Proto:   ncasn.Tls,
	}

	if meta.ToPrefix() != "_http._tls" {
		t.Error("Wrong prefix")
	}
}

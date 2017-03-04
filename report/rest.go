/* Vuls - Vulnerability Scanner
Copyright (C) 2017 Federacy, Inc

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package report

import (
	"encoding/json"
	"fmt"
	"time"

//	log "github.com/Sirupsen/logrus"
	"github.com/cenkalti/backoff"
	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/parnurzeal/gorequest"
)

// RestWriter send report to a REST API
type RestWriter struct{}

func (w RestWriter) Write(rs ...models.ScanResult) error {
	conf := config.Conf.Rest
        token := conf.Token
	email := conf.Email
        url := conf.Url
        hostid := conf.Hostid
	for _, r := range rs {
		bytes, _ := json.Marshal(r)
		jsonBody := string(bytes)
		f := func() (err error) {
			resp, body, errs := gorequest.New().Proxy(config.Conf.HTTPProxy).Post(url).Set("X-User-Token", token).Set("X-User-Email", email).Set("HostID", hostid).Send(string(jsonBody)).End()
			if 0 < len(errs) || resp == nil || resp.StatusCode != 200 {
				return fmt.Errorf(
					"HTTP POST error: %v, url: %s, resp: %v, body: %s",
					errs, url, resp, body)
			}
			return nil
		}
		notify := func(err error, t time.Duration) {
		// 	This was writing to the wrong directory (localhost instead of hostname)
		//	log.Warn("Error %s", err)
		//	log.Warn("Retrying in ", t)
		}
		if err := backoff.RetryNotify(f, backoff.NewExponentialBackOff(), notify); err != nil {
			return fmt.Errorf("HTTP Error: %s", err)
		}
	}
	return nil
}


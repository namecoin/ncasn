package contrasub

import "errors"

var ErrNotHidden = errors.New("not a hidden domain records zone")
var ErrVisibleRecordsPresent = errors.New("zone contains visible domain records")
var ErrTooManySubdomains = errors.New("too many subdomains")

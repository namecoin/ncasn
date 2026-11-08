package contrasub

import "errors"

var NotHiddenError = errors.New("not a hidden domain records zone")
var VisibleRecordsPresentError = errors.New("zone contains visible domain records")

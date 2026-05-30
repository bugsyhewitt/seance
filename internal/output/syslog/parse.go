// Parser helpers for the operator-facing facility and severity strings. Kept
// in a small, dependency-free file so the test suite can exercise the mapping
// without touching the worker or the network.
//
//go:build !windows && !plan9

package syslog

import (
	"fmt"
	"log/syslog"
	"strings"
)

// facilities maps the operator-facing facility name (case-insensitive, no
// "LOG_" prefix) to the stdlib syslog.Priority constant. The set is the
// standard RFC5424 facilities most syslog implementations understand, with the
// eight LOCAL channels exposed so security teams can carve out a dedicated
// route for séance findings.
var facilities = map[string]syslog.Priority{
	"kern":     syslog.LOG_KERN,
	"user":     syslog.LOG_USER,
	"mail":     syslog.LOG_MAIL,
	"daemon":   syslog.LOG_DAEMON,
	"auth":     syslog.LOG_AUTH,
	"syslog":   syslog.LOG_SYSLOG,
	"lpr":      syslog.LOG_LPR,
	"news":     syslog.LOG_NEWS,
	"uucp":     syslog.LOG_UUCP,
	"cron":     syslog.LOG_CRON,
	"authpriv": syslog.LOG_AUTHPRIV,
	"ftp":      syslog.LOG_FTP,
	"local0":   syslog.LOG_LOCAL0,
	"local1":   syslog.LOG_LOCAL1,
	"local2":   syslog.LOG_LOCAL2,
	"local3":   syslog.LOG_LOCAL3,
	"local4":   syslog.LOG_LOCAL4,
	"local5":   syslog.LOG_LOCAL5,
	"local6":   syslog.LOG_LOCAL6,
	"local7":   syslog.LOG_LOCAL7,
}

// severities maps the operator-facing severity name (case-insensitive, no
// "LOG_" prefix) to the stdlib syslog.Priority severity bits. Only the eight
// RFC5424 severities are accepted.
var severities = map[string]syslog.Priority{
	"emerg":   syslog.LOG_EMERG,
	"alert":   syslog.LOG_ALERT,
	"crit":    syslog.LOG_CRIT,
	"err":     syslog.LOG_ERR,
	"error":   syslog.LOG_ERR,
	"warning": syslog.LOG_WARNING,
	"warn":    syslog.LOG_WARNING,
	"notice":  syslog.LOG_NOTICE,
	"info":    syslog.LOG_INFO,
	"debug":   syslog.LOG_DEBUG,
}

// ParseFacility maps an operator-facing facility name (e.g. "local0", "user",
// case-insensitive) to the stdlib syslog.Priority constant. An empty string
// returns the default facility (LOG_USER) with no error — empty means "leave
// the default in place". An unrecognised name returns an error so a typo
// surfaces at startup instead of silently routing findings to the wrong
// channel.
func ParseFacility(name string) (syslog.Priority, error) {
	if name == "" {
		return defaultFacility, nil
	}
	p, ok := facilities[strings.ToLower(strings.TrimSpace(name))]
	if !ok {
		return 0, fmt.Errorf("unknown syslog facility %q (valid: kern,user,mail,daemon,auth,syslog,lpr,news,uucp,cron,authpriv,ftp,local0..local7)", name)
	}
	return p, nil
}

// ParseSeverity maps an operator-facing severity name to the stdlib
// syslog.Priority severity bits. An empty string returns 0, the sentinel that
// tells the sink to derive severity from finding confidence. An unrecognised
// name returns an error.
func ParseSeverity(name string) (syslog.Priority, error) {
	if name == "" {
		return 0, nil
	}
	p, ok := severities[strings.ToLower(strings.TrimSpace(name))]
	if !ok {
		return 0, fmt.Errorf("unknown syslog severity %q (valid: emerg,alert,crit,err,warning,notice,info,debug)", name)
	}
	return p, nil
}

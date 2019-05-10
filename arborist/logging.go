package arborist

import (
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
)

type Logger interface {
	Debug(string, ...interface{})
	Info(string, ...interface{})
	Warning(string, ...interface{})
	Error(string, ...interface{})
}

type LogHandler struct {
	logger *log.Logger
}

func (handler *LogHandler) Debug(format string, a ...interface{}) {
	if len(a) > 0 {
		msg := fmt.Sprintf(format, a...)
		handler.logger.Printf("DEBUG: %s", msg)
	} else {
		handler.logger.Printf("DEBUG: %s", format)
	}
}

func (handler *LogHandler) Info(format string, a ...interface{}) {
	if len(a) > 0 {
		msg := fmt.Sprintf(format, a...)
		handler.logger.Printf("INFO: %s", msg)
	} else {
		handler.logger.Printf("INFO: %s", format)
	}
}

func (handler *LogHandler) Warning(format string, a ...interface{}) {
	if len(a) > 0 {
		msg := fmt.Sprintf(format, a...)
		handler.logger.Printf("WARNING: %s", msg)
	} else {
		handler.logger.Printf("WARNING: %s", format)
	}
}

func (handler *LogHandler) Error(format string, a ...interface{}) {
	if len(a) > 0 {
		msg := fmt.Sprintf(format, a...)
		handler.logger.Printf("ERROR: %s", msg)
	} else {
		handler.logger.Printf("ERROR: %s", format)
	}
}

type LogLevel string

const (
	LogLevelDebug   = "DEBUG"
	LogLevelInfo    = "INFO"
	LogLevelWarning = "WARNING"
	LogLevelError   = "ERROR"
)

type Log struct {
	lvl LogLevel
	msg string
}

type LogCache struct {
	logs []Log
}

func (cache *LogCache) write(logger Logger) {
	for _, log := range cache.logs {
		switch log.lvl {
		case LogLevelDebug:
			logger.Debug(log.msg)
		case LogLevelInfo:
			logger.Info(log.msg)
		case LogLevelWarning:
			logger.Warning(log.msg)
		case LogLevelError:
			logger.Error(log.msg)
		}
	}
}

func logMsg(lvl LogLevel, format string, a ...interface{}) string {
	var msg string
	if len(a) == 0 {
		msg = format
	} else {
		msg = fmt.Sprintf(format, a...)
	}
	// get the call from 2 stack frames above this
	// (one call up is the LogCache method, so go one more above that)
	_, fn, line, ok := runtime.Caller(2)
	if ok {
		// shorten the filepath to only the basename
		split := strings.Split(fn, string(os.PathSeparator))
		fn = split[len(split)-1]
		msg = fmt.Sprintf("%s:%d: %s", fn, line, msg)
	}
	return msg
}

func (cache *LogCache) Debug(format string, a ...interface{}) {
	log := Log{
		lvl: LogLevelDebug,
		msg: logMsg(LogLevelDebug, format, a...),
	}
	cache.logs = append(cache.logs, log)
}

func (cache *LogCache) Info(format string, a ...interface{}) {
	log := Log{
		lvl: LogLevelInfo,
		msg: logMsg(LogLevelInfo, format, a...),
	}
	cache.logs = append(cache.logs, log)
}

func (cache *LogCache) Warning(format string, a ...interface{}) {
	log := Log{
		lvl: LogLevelWarning,
		msg: logMsg(LogLevelWarning, format, a...),
	}
	cache.logs = append(cache.logs, log)
}

func (cache *LogCache) Error(format string, a ...interface{}) {
	log := Log{
		lvl: LogLevelError,
		msg: logMsg(LogLevelError, format, a...),
	}
	cache.logs = append(cache.logs, log)
}

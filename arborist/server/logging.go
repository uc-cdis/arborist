package server

import (
	"fmt"
	"io"
	"log"
)

type LogHandler struct {
	logger *log.Logger
}

func NewLogHandler(out io.Writer, flags int) *LogHandler {
	if flags == 0 {
		flags = log.Ldate | log.Ltime | log.Llongfile
	}
	return &LogHandler{
		logger: log.New(out, "", flags),
	}
}

func (handler *LogHandler) Debug(format string, a ...interface{}) {
	if len(a) > 0 {
		msg := fmt.Sprintf(format, a)
		handler.logger.Print(fmt.Sprintf("DEBUG: %s", msg))
	} else {
		handler.logger.Print("DEBUG: %s", format)
	}
}

func (handler *LogHandler) Info(format string, a ...interface{}) {
	if len(a) > 0 {
		msg := fmt.Sprintf(format, a)
		handler.logger.Print(fmt.Sprintf("INFO: %s", msg))
	} else {
		handler.logger.Print("INFO: %s", format)
	}
}

func (handler *LogHandler) Warning(format string, a ...interface{}) {
	if len(a) > 0 {
		msg := fmt.Sprintf(format, a)
		handler.logger.Print(fmt.Sprintf("WARNING: %s", msg))
	} else {
		handler.logger.Print("WARNING: %s", format)
	}
}

func (handler *LogHandler) Error(format string, a ...interface{}) {
	if len(a) > 0 {
		msg := fmt.Sprintf(format, a)
		handler.logger.Print(fmt.Sprintf("ERROR: %s", msg))
	} else {
		handler.logger.Print("ERROR: %s", format)
	}
}

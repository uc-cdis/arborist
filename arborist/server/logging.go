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
	msg := fmt.Sprintf(format, a)
	handler.logger.Print(fmt.Sprintf("DEBUG: %s", msg))
}

func (handler *LogHandler) Info(format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a)
	handler.logger.Print(fmt.Sprintf("INFO: %s", msg))
}

func (handler *LogHandler) Warning(format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a)
	handler.logger.Print(fmt.Sprintf("WARNING: %s", msg))
}

func (handler *LogHandler) Error(format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a)
	handler.logger.Print(fmt.Sprintf("ERROR: %s", msg))
}

package arborist

import (
	"fmt"
	"log"
)

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

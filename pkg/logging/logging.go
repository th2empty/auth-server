package logging

import (
	"fmt"
	"github.com/sirupsen/logrus"
	"io"
	"os"
	"runtime"
	"time"
)

type writerHook struct {
	Writer    []io.Writer
	LogLevels []logrus.Level
}

func (h *writerHook) Fire(entry *logrus.Entry) error {
	line, err := entry.String()
	if err != nil {
		return err
	}

	for _, w := range h.Writer {
		w.Write([]byte(line))
	}

	return err
}

func (h *writerHook) Levels() []logrus.Level {
	return h.LogLevels
}

var entry *logrus.Entry

type Logger struct {
	*logrus.Entry
}

func GetLogger() Logger {
	return Logger{entry}
}

func (l *Logger) GetLoggerWithField(k string, v interface{}) Logger {
	return Logger{l.WithField(k, v)}
}

func init() {
	log := logrus.New()
	log.SetReportCaller(true)
	log.SetFormatter(&logrus.TextFormatter{
		ForceColors:     true,
		DisableColors:   true,
		FullTimestamp:   true,
		TimestampFormat: "02/01/2006 15:04:05",
		ForceQuote:      true,

		CallerPrettyfier: func(frame *runtime.Frame) (function string, file string) {
			return fmt.Sprintf("%s()", frame.Function), fmt.Sprintf("%s:%d", frame.File, frame.Line)
		},
	})

	if err := os.MkdirAll("logs", 0644); err != nil {
		panic(err)
	}

	logFile, err := os.OpenFile(
		fmt.Sprintf("logs/%d.log", time.Now().Unix()),
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)

	if err != nil {
		panic(err)
	}

	log.SetOutput(io.Discard)
	log.AddHook(&writerHook{
		Writer:    []io.Writer{logFile, os.Stdout},
		LogLevels: logrus.AllLevels,
	})
	log.SetLevel(logrus.TraceLevel)

	entry = logrus.NewEntry(log)
}

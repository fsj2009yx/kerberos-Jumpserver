package log

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"strings"
	"time"

	goliblog "github.com/fatedier/golib/log"
)

var (
	TraceLevel = goliblog.TraceLevel
	DebugLevel = goliblog.DebugLevel
	InfoLevel  = goliblog.InfoLevel
	WarnLevel  = goliblog.WarnLevel
	ErrorLevel = goliblog.ErrorLevel
)

const defaultMaxLogDays = 3

var Logger *goliblog.Logger

func init() {
	Logger = goliblog.New(
		goliblog.WithCaller(true),
		goliblog.AddCallerSkip(1),
		goliblog.WithLevel(goliblog.InfoLevel),
	)
}

func InitLogger(logPath string, levelStr string, maxDays int, disableLogColor bool) {
	options := []goliblog.Option{}
	outputs := []io.Writer{
		goliblog.NewConsoleWriter(goliblog.ConsoleConfig{
			Colorful: !disableLogColor,
		}, os.Stdout),
	}

	logPath = strings.TrimSpace(logPath)
	if logPath != "" && logPath != "console" {
		if maxDays <= 0 {
			maxDays = defaultMaxLogDays
		}
		writer := goliblog.NewRotateFileWriter(goliblog.RotateFileConfig{
			FileName: logPath,
			Mode:     goliblog.RotateFileModeDaily,
			MaxDays:  maxDays,
		})
		writer.Init()
		outputs = append(outputs, writer)
	}
	if len(outputs) == 1 {
		options = append(options, goliblog.WithOutput(outputs[0]))
	} else {
		options = append(options, goliblog.WithOutput(multiWriter(outputs)))
	}

	level, err := goliblog.ParseLevel(levelStr)
	if err != nil {
		level = goliblog.InfoLevel
	}
	options = append(options, goliblog.WithLevel(level))
	Logger = Logger.WithOptions(options...)
}

func InitLoggerFromConfigFile(configPath string) {
	cfg := struct {
		LogLevel        string `json:"log_level"`
		LogFile         string `json:"log_file"`
		LogMaxDays      int    `json:"log_max_days"`
		DisableLogColor bool   `json:"disable_log_color"`
	}{
		LogLevel:   InfoLevel.String(),
		LogFile:    "console",
		LogMaxDays: defaultMaxLogDays,
	}
	b, err := os.ReadFile(configPath)
	if err != nil {
		InitLogger(cfg.LogFile, cfg.LogLevel, cfg.LogMaxDays, cfg.DisableLogColor)
		Warnf("read log config failed path=%s err=%v", configPath, err)
		return
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		InitLogger(cfg.LogFile, cfg.LogLevel, cfg.LogMaxDays, cfg.DisableLogColor)
		Warnf("parse log config failed path=%s err=%v", configPath, err)
		return
	}
	InitLogger(cfg.LogFile, cfg.LogLevel, cfg.LogMaxDays, cfg.DisableLogColor)
}

func Errorf(format string, v ...any) {
	Logger.Errorf(format, v...)
}

func Warnf(format string, v ...any) {
	Logger.Warnf(format, v...)
}

func Infof(format string, v ...any) {
	Logger.Infof(format, v...)
}

func Debugf(format string, v ...any) {
	Logger.Debugf(format, v...)
}

func Tracef(format string, v ...any) {
	Logger.Tracef(format, v...)
}

func Logf(level goliblog.Level, offset int, format string, v ...any) {
	Logger.Logf(level, offset, format, v...)
}

type WriteLogger struct {
	level  goliblog.Level
	offset int
}

func NewWriteLogger(level goliblog.Level, offset int) *WriteLogger {
	return &WriteLogger{
		level:  level,
		offset: offset,
	}
}

func (w *WriteLogger) Write(p []byte) (n int, err error) {
	Logger.Log(w.level, w.offset, string(bytes.TrimRight(p, "\n")))
	return len(p), nil
}

type logWriter interface {
	WriteLog([]byte, goliblog.Level, time.Time) (int, error)
}

type fanoutWriter []io.Writer

func multiWriter(writers []io.Writer) fanoutWriter {
	out := make(fanoutWriter, 0, len(writers))
	for _, writer := range writers {
		if writer != nil {
			out = append(out, writer)
		}
	}
	return out
}

func (fw fanoutWriter) Write(p []byte) (int, error) {
	return fw.WriteLog(p, InfoLevel, time.Now())
}

func (fw fanoutWriter) WriteLog(p []byte, level goliblog.Level, when time.Time) (int, error) {
	for _, writer := range fw {
		var err error
		if lw, ok := writer.(logWriter); ok {
			_, err = lw.WriteLog(p, level, when)
		} else {
			_, err = writer.Write(p)
		}
		if err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

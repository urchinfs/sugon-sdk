/*
 *     Copyright 2020 The Dragonfly Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package dflog

import (
	"fmt"
	"os"
	"strconv"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"google.golang.org/grpc/grpclog"
)

var (
	CoreLogger       *zap.SugaredLogger
	GrpcLogger       *zap.SugaredLogger
	GinLogger        *zap.SugaredLogger
	GCLogger         *zap.SugaredLogger
	StorageGCLogger  *zap.SugaredLogger
	JobLogger        *zap.SugaredLogger
	KeepAliveLogger  *zap.SugaredLogger
	StatSeedLogger   *zap.Logger
	DownloaderLogger *zap.Logger

	coreLogLevelEnabler zapcore.LevelEnabler
)

func init() {
	config := zap.NewDevelopmentConfig()
	config.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	log, err := config.Build(zap.AddCaller(), zap.AddStacktrace(zap.WarnLevel), zap.AddCallerSkip(1))
	if err == nil {
		sugar := log.Sugar()
		SetCoreLogger(sugar)
		SetGrpcLogger(sugar)
		SetGinLogger(sugar)
		SetGCLogger(sugar)
		SetStorageGCLogger(sugar)
		SetKeepAliveLogger(sugar)
		SetStatSeedLogger(log)
		SetDownloadLogger(log)
		SetJobLogger(sugar)
	}
	levels = append(levels, config.Level)
}

// SetLevel updates all log level
func SetLevel(level zapcore.Level) {
	Infof("change log level to %s", level.String())
	for _, l := range levels {
		l.SetLevel(level)
	}
}

func SetCoreLogger(log *zap.SugaredLogger) {
	CoreLogger = log
	coreLogLevelEnabler = log.Desugar().Core()
}

func SetGCLogger(log *zap.SugaredLogger) {
	GCLogger = log
}

func SetStorageGCLogger(log *zap.SugaredLogger) {
	StorageGCLogger = log
}

func SetKeepAliveLogger(log *zap.SugaredLogger) {
	KeepAliveLogger = log
}

func SetStatSeedLogger(log *zap.Logger) {
	StatSeedLogger = log
}

func SetDownloadLogger(log *zap.Logger) {
	DownloaderLogger = log
}

func SetGrpcLogger(log *zap.SugaredLogger) {
	GrpcLogger = log
	var v int
	vLevel := os.Getenv("GRPC_GO_LOG_VERBOSITY_LEVEL")
	if vl, err := strconv.Atoi(vLevel); err == nil {
		v = vl
	}
	grpclog.SetLoggerV2(&zapGrpc{GrpcLogger, v})
}

func SetGinLogger(log *zap.SugaredLogger) {
	GinLogger = log
}

func SetJobLogger(log *zap.SugaredLogger) {
	JobLogger = log
}

type SugaredLoggerOnWith struct {
	withArgs []any
}

func With(args ...any) *SugaredLoggerOnWith {
	return &SugaredLoggerOnWith{
		withArgs: args,
	}
}

func WithHostID(hostID string) *SugaredLoggerOnWith {
	return &SugaredLoggerOnWith{
		withArgs: []any{"hostID", hostID},
	}
}

func WithTaskID(taskID string) *SugaredLoggerOnWith {
	return &SugaredLoggerOnWith{
		withArgs: []any{"taskID", taskID},
	}
}

func WithTaskAndPeerID(taskID, peerID string) *SugaredLoggerOnWith {
	return &SugaredLoggerOnWith{
		withArgs: []any{"taskID", taskID, "peerID", peerID},
	}
}

func WithTaskIDAndURL(taskID, url string) *SugaredLoggerOnWith {
	return &SugaredLoggerOnWith{
		withArgs: []any{"taskID", taskID, "url", url},
	}
}

func WithHostnameAndIP(hostname, ip string) *SugaredLoggerOnWith {
	return &SugaredLoggerOnWith{
		withArgs: []any{"hostname", hostname, "ip", ip},
	}
}

func WithTaskAndJobID(taskID, jobID string) *SugaredLoggerOnWith {
	return &SugaredLoggerOnWith{
		withArgs: []any{"taskID", taskID, "jobID", jobID},
	}
}

func (log *SugaredLoggerOnWith) With(args ...any) *SugaredLoggerOnWith {
	args = append(args, log.withArgs...)
	return &SugaredLoggerOnWith{
		withArgs: args,
	}
}

func (log *SugaredLoggerOnWith) Infof(template string, args ...any) {
	if !coreLogLevelEnabler.Enabled(zap.InfoLevel) {
		return
	}
	CoreLogger.Infow(fmt.Sprintf(template, args...), log.withArgs...)
}

func (log *SugaredLoggerOnWith) Info(args ...any) {
	if !coreLogLevelEnabler.Enabled(zap.InfoLevel) {
		return
	}
	CoreLogger.Infow(fmt.Sprint(args...), log.withArgs...)
}

func (log *SugaredLoggerOnWith) Warnf(template string, args ...any) {
	if !coreLogLevelEnabler.Enabled(zap.WarnLevel) {
		return
	}
	CoreLogger.Warnw(fmt.Sprintf(template, args...), log.withArgs...)
}

func (log *SugaredLoggerOnWith) Warn(args ...any) {
	if !coreLogLevelEnabler.Enabled(zap.WarnLevel) {
		return
	}
	CoreLogger.Warnw(fmt.Sprint(args...), log.withArgs...)
}

func (log *SugaredLoggerOnWith) Errorf(template string, args ...any) {
	if !coreLogLevelEnabler.Enabled(zap.ErrorLevel) {
		return
	}
	CoreLogger.Errorw(fmt.Sprintf(template, args...), log.withArgs...)
}

func (log *SugaredLoggerOnWith) Error(args ...any) {
	if !coreLogLevelEnabler.Enabled(zap.ErrorLevel) {
		return
	}
	CoreLogger.Errorw(fmt.Sprint(args...), log.withArgs...)
}

func (log *SugaredLoggerOnWith) Debugf(template string, args ...any) {
	if !coreLogLevelEnabler.Enabled(zap.DebugLevel) {
		return
	}
	CoreLogger.Debugw(fmt.Sprintf(template, args...), log.withArgs...)
}

func (log *SugaredLoggerOnWith) Debug(args ...any) {
	if !coreLogLevelEnabler.Enabled(zap.DebugLevel) {
		return
	}
	CoreLogger.Debugw(fmt.Sprint(args...), log.withArgs...)
}

func (log *SugaredLoggerOnWith) IsDebug() bool {
	return coreLogLevelEnabler.Enabled(zap.DebugLevel)
}

func Infof(template string, args ...any) {
	CoreLogger.Infof(template, args...)
}

func Info(args ...any) {
	CoreLogger.Info(args...)
}

func Warnf(template string, args ...any) {
	CoreLogger.Warnf(template, args...)
}

func Warn(args ...any) {
	CoreLogger.Warn(args...)
}

func Errorf(template string, args ...any) {
	CoreLogger.Errorf(template, args...)
}

func Error(args ...any) {
	CoreLogger.Error(args...)
}

func Debugf(template string, args ...any) {
	CoreLogger.Debugf(template, args...)
}

func Debug(args ...any) {
	CoreLogger.Debug(args...)
}

func IsDebug() bool {
	return coreLogLevelEnabler.Enabled(zap.DebugLevel)
}

func Fatalf(template string, args ...any) {
	CoreLogger.Fatalf(template, args...)
}

func Fatal(args ...any) {
	CoreLogger.Fatal(args...)
}

type zapGrpc struct {
	*zap.SugaredLogger
	verbose int
}

func (z *zapGrpc) Infoln(args ...any) {
	z.SugaredLogger.Info(args...)
}

func (z *zapGrpc) Warning(args ...any) {
	z.SugaredLogger.Warn(args...)
}

func (z *zapGrpc) Warningln(args ...any) {
	z.SugaredLogger.Warn(args...)
}

func (z *zapGrpc) Warningf(format string, args ...any) {
	z.SugaredLogger.Warnf(format, args...)
}

func (z *zapGrpc) Errorln(args ...any) {
	z.SugaredLogger.Error(args...)
}

func (z *zapGrpc) Fatalln(args ...any) {
	z.SugaredLogger.Fatal(args...)
}

func (z *zapGrpc) V(level int) bool {
	return level <= z.verbose
}

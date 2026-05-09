package policy

import (
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/mayjain/aegis/internal/extract"
)

// BuildDefaultPipeline constructs the standard policy pipeline with an OPA step.
// It tries to load Rego from policies/rego/aegis.rego + data.json first.
// If those files don't exist, falls back to the inline DefaultRegoModule.
func BuildDefaultPipeline(cmdDBPath string, logger *slog.Logger) *Pipeline {
	var db *extract.CommandDB
	if cmdDBPath != "" {
		var err error
		db, err = extract.LoadCommandDB(cmdDBPath)
		if err != nil {
			logger.Warn("pipeline: failed to load command db, extraction will be limited", "error", err)
		}
	}

	ext := extract.NewExtractor(db)
	pipeline := NewPipeline(ext, ActionDeny)

	// Resolve rego paths relative to command DB directory (or CWD)
	regoDir := "policies/rego"
	if cmdDBPath != "" {
		regoDir = filepath.Join(filepath.Dir(filepath.Dir(cmdDBPath)), "rego")
	}
	regoPath := filepath.Join(regoDir, "aegis.rego")
	dataPath := filepath.Join(regoDir, "data.json")

	var opaStep *OPAStep
	var err error
	hasRegoFiles := false

	if _, statErr := os.Stat(regoPath); statErr == nil {
		hasRegoFiles = true
		opaStep, err = NewOPAStepFromFiles(regoPath, dataPath)
		if err != nil {
			logger.Warn("pipeline: failed to load rego files, falling back to inline", "error", err)
			opaStep = nil
			hasRegoFiles = false
		} else {
			logger.Info("pipeline: OPA step loaded from files", "rego", regoPath, "data", dataPath)
		}
	}

	if opaStep == nil {
		opaStep, err = NewOPAStep(DefaultRegoModule, nil)
		if err != nil {
			logger.Error("pipeline: failed to compile inline OPA policy, pipeline will be no-op", "error", err)
			return pipeline
		}
		logger.Info("pipeline: OPA step initialized with inline policy")
	}

	pipeline.AddStep(&RateLimitStep{MaxPerMinute: 60})
	pipeline.AddStep(&SelfProtectStep{})
	pipeline.AddStep(NewDLPStep())
	pipeline.AddStep(opaStep)

	logger.Info("pipeline: fully initialized",
		"steps", []string{"rate_limit", "self_protect", "dlp", "opa"})

	if hasRegoFiles {
		go watchRegoFiles(regoPath, dataPath, opaStep, logger)
	}

	return pipeline
}

// watchRegoFiles polls Rego policy files and reloads OPA on change.
func watchRegoFiles(regoPath, dataPath string, step *OPAStep, logger *slog.Logger) {
	var lastMod time.Time
	if info, err := os.Stat(regoPath); err == nil {
		lastMod = info.ModTime()
	}

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		changed := false

		if info, err := os.Stat(regoPath); err == nil && info.ModTime().After(lastMod) {
			changed = true
			lastMod = info.ModTime()
		}
		if !changed && dataPath != "" {
			if info, err := os.Stat(dataPath); err == nil && info.ModTime().After(lastMod) {
				changed = true
				lastMod = info.ModTime()
			}
		}

		if !changed {
			continue
		}

		if err := step.ReloadFromFiles(regoPath, dataPath); err != nil {
			logger.Error("opa hot-reload failed, keeping old policy", "error", err)
		} else {
			logger.Info("opa policy reloaded", "rego", regoPath)
		}
	}
}

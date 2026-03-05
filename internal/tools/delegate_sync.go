package tools

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/nextlevelbuilder/goclaw/internal/store"
	"github.com/nextlevelbuilder/goclaw/internal/tracing"
)

// Delegate executes a synchronous delegation to another agent.
func (dm *DelegateManager) Delegate(ctx context.Context, opts DelegateOpts) (*DelegateResult, error) {
	task, _, err := dm.prepareDelegation(ctx, opts, "sync")
	if err != nil {
		return nil, err
	}

	dm.active.Store(task.ID, task)
	defer func() {
		now := time.Now()
		task.CompletedAt = &now
		dm.active.Delete(task.ID)
	}()

	dm.injectDependencyResults(ctx, &opts)
	message := buildDelegateMessage(opts)
	dm.emitEvent("delegation.started", task)
	slog.Info("delegation started", "id", task.ID, "target", opts.TargetAgentKey, "mode", "sync")

	// Propagate parent trace ID so the delegate trace links back.
	// Clear senderID — delegations are system-initiated, the delegate agent
	// should not inherit the caller's group writer permissions (the delegate
	// agent has its own writer list, and would incorrectly deny writes).
	delegateCtx := store.WithSenderID(ctx, "")
	if parentTraceID := tracing.TraceIDFromContext(ctx); parentTraceID != uuid.Nil {
		delegateCtx = tracing.WithDelegateParentTraceID(delegateCtx, parentTraceID)
	}

	startTime := time.Now()
	result, err := dm.runAgent(delegateCtx, opts.TargetAgentKey, dm.buildRunRequest(task, message))
	duration := time.Since(startTime)
	if err != nil {
		task.Status = "failed"
		dm.emitEvent("delegation.failed", task)
		dm.saveDelegationHistory(task, "", err, duration)
		return nil, fmt.Errorf("delegation to %q failed: %w", opts.TargetAgentKey, err)
	}

	// Apply quality gates before marking completed.
	if result, err = dm.applyQualityGates(delegateCtx, task, opts, result); err != nil {
		task.Status = "failed"
		dm.emitEvent("delegation.failed", task)
		dm.saveDelegationHistory(task, "", err, duration)
		return nil, fmt.Errorf("delegation to %q failed quality gate: %w", opts.TargetAgentKey, err)
	}

	task.Status = "completed"
	dm.emitEvent("delegation.completed", task)
	dm.trackCompleted(task)
	dm.autoCompleteTeamTask(task, result.Content, result.Deliverables)
	dm.saveDelegationHistory(task, result.Content, nil, duration)
	slog.Info("delegation completed", "id", task.ID, "target", opts.TargetAgentKey, "iterations", result.Iterations)

	return &DelegateResult{Content: result.Content, Iterations: result.Iterations, DelegationID: task.ID, TeamTaskID: task.TeamTaskID.String(), MediaPaths: result.MediaPaths}, nil
}

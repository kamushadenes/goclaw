package tools

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/nextlevelbuilder/goclaw/internal/store"
)

func TestProcessPendingTasksDispatchesOnlyOneTaskPerOwner(t *testing.T) {
	mb, _, _, _, ctx := newTestTeamSetup()
	manager := NewTeamToolManager(mb.taskStore, nil, nil, "/tmp/test")
	manager.agentCache.Store(testMemberID, &agentCacheEntry{
		agent: &store.AgentData{
			BaseModel: store.BaseModel{ID: testMemberID},
			AgentKey:  "member-agent",
		},
		cachedAt: time.Now(),
	})
	manager.agentCache.Store(testMember2ID, &agentCacheEntry{
		agent: &store.AgentData{
			BaseModel: store.BaseModel{ID: testMember2ID},
			AgentKey:  "member2-agent",
		},
		cachedAt: time.Now(),
	})

	firstForMember := &store.TeamTaskData{
		TeamID:       testTeamID,
		Subject:      "first member task",
		Status:       store.TeamTaskStatusPending,
		OwnerAgentID: &testMemberID,
		Metadata:     map[string]any{},
	}
	secondForMember := &store.TeamTaskData{
		TeamID:       testTeamID,
		Subject:      "second member task",
		Status:       store.TeamTaskStatusPending,
		OwnerAgentID: &testMemberID,
		Metadata:     map[string]any{},
	}
	firstForMember2 := &store.TeamTaskData{
		TeamID:       testTeamID,
		Subject:      "first member2 task",
		Status:       store.TeamTaskStatusPending,
		OwnerAgentID: &testMember2ID,
		Metadata:     map[string]any{},
	}
	if err := mb.taskStore.CreateTask(ctx, firstForMember); err != nil {
		t.Fatalf("create firstForMember: %v", err)
	}
	if err := mb.taskStore.CreateTask(ctx, secondForMember); err != nil {
		t.Fatalf("create secondForMember: %v", err)
	}
	if err := mb.taskStore.CreateTask(ctx, firstForMember2); err != nil {
		t.Fatalf("create firstForMember2: %v", err)
	}

	err := manager.ProcessPendingTasks(ctx, testTeamID, []uuid.UUID{
		firstForMember.ID,
		secondForMember.ID,
		firstForMember2.ID,
	})
	if err != nil {
		t.Fatalf("ProcessPendingTasks: %v", err)
	}

	if got := readTask(mb, firstForMember.ID).Status; got != store.TeamTaskStatusInProgress {
		t.Fatalf("first same-owner task status = %q, want %q", got, store.TeamTaskStatusInProgress)
	}
	if got := readTask(mb, secondForMember.ID).Status; got != store.TeamTaskStatusPending {
		t.Fatalf("second same-owner task status = %q, want %q", got, store.TeamTaskStatusPending)
	}
	if got := readTask(mb, firstForMember2.ID).Status; got != store.TeamTaskStatusInProgress {
		t.Fatalf("different-owner task status = %q, want %q", got, store.TeamTaskStatusInProgress)
	}
}

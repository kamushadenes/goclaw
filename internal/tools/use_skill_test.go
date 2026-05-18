package tools

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/nextlevelbuilder/goclaw/internal/skills"
	"github.com/nextlevelbuilder/goclaw/internal/store"
)

type fakeSkillAccessStore struct {
	skills []store.SkillInfo
	err    error
}

func (f fakeSkillAccessStore) ListAccessible(context.Context, uuid.UUID, string) ([]store.SkillInfo, error) {
	return f.skills, f.err
}

func TestUseSkillReturnsSkillContentAndReferences(t *testing.T) {
	loader := newTestSkillLoader(t, "product-skill", "Product Skill")
	tool := NewUseSkillTool(loader)

	result := tool.Execute(context.Background(), map[string]any{"name": "Product Skill"})

	if result.IsError {
		t.Fatalf("Execute() returned error: %s", result.ForLLM)
	}
	for _, want := range []string{
		`Skill "product-skill" activated.`,
		"Main body for product skill.",
		"references/details.md",
		"Reference body.",
	} {
		if !strings.Contains(result.ForLLM, want) {
			t.Fatalf("result missing %q:\n%s", want, result.ForLLM)
		}
	}
	if strings.Contains(result.ForLLM, "description:") {
		t.Fatalf("frontmatter should be stripped from SKILL.md content:\n%s", result.ForLLM)
	}
}

func TestUseSkillRejectsInaccessibleManagedSkill(t *testing.T) {
	loader := newTestSkillLoader(t, "private-skill", "Private Skill")
	tool := NewUseSkillTool(loader)
	tool.SetSkillAccessStore(fakeSkillAccessStore{})
	ctx := store.WithAgentID(context.Background(), uuid.New())

	result := tool.Execute(ctx, map[string]any{"name": "private-skill"})

	if !result.IsError || !strings.Contains(result.ForLLM, "not accessible") {
		t.Fatalf("expected inaccessible error, got error=%v output=%q", result.IsError, result.ForLLM)
	}
}

func TestUseSkillAllowsAccessStoreFailures(t *testing.T) {
	loader := newTestSkillLoader(t, "product-skill", "Product Skill")
	tool := NewUseSkillTool(loader)
	tool.SetSkillAccessStore(fakeSkillAccessStore{err: errors.New("db down")})
	ctx := store.WithAgentID(context.Background(), uuid.New())

	result := tool.Execute(ctx, map[string]any{"name": "product-skill"})

	if result.IsError {
		t.Fatalf("access-store failure should not block skill use, got: %s", result.ForLLM)
	}
	if !strings.Contains(result.ForLLM, "Main body for product skill.") {
		t.Fatalf("result missing skill content: %s", result.ForLLM)
	}
}

func newTestSkillLoader(t *testing.T, slug, frontmatterName string) *skills.Loader {
	t.Helper()

	root := t.TempDir()
	workspace := filepath.Join(root, "workspace")
	global := filepath.Join(root, "global")
	builtin := filepath.Join(root, "builtin")
	managed := filepath.Join(root, "managed")
	for _, dir := range []string{workspace, global, builtin} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	skillDir := filepath.Join(managed, slug, "1")
	refDir := filepath.Join(skillDir, "references")
	if err := os.MkdirAll(refDir, 0o755); err != nil {
		t.Fatal(err)
	}
	skill := "---\nname: " + frontmatterName + "\ndescription: Use when testing use_skill.\n---\n\n# Product Skill\n\nMain body for product skill.\n"
	if err := os.WriteFile(filepath.Join(skillDir, "SKILL.md"), []byte(skill), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(refDir, "details.md"), []byte("# Details\n\nReference body.\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	loader := skills.NewLoader(workspace, global, builtin)
	loader.SetManagedDir(managed)
	return loader
}

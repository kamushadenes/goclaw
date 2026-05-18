package tools

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/google/uuid"

	"github.com/nextlevelbuilder/goclaw/internal/skills"
	"github.com/nextlevelbuilder/goclaw/internal/store"
)

// UseSkillTool activates a skill and returns its instructions.
// It generates tool.call / tool.result events in spans and realtime
// so skill activation is visible in tracing. Returning the skill body here
// lets agents use skills even when read_file is not enabled for the run.
type UseSkillTool struct {
	loader      *skills.Loader
	skillAccess store.SkillAccessStore
}

func NewUseSkillTool(loader *skills.Loader) *UseSkillTool {
	return &UseSkillTool{loader: loader}
}

func (t *UseSkillTool) SetSkillAccessStore(sas store.SkillAccessStore) {
	t.skillAccess = sas
}

func (t *UseSkillTool) Name() string { return "use_skill" }

func (t *UseSkillTool) Description() string {
	return "Activate a skill and return its instructions. Call this before following a skill-specific workflow."
}

func (t *UseSkillTool) Parameters() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"name": map[string]any{
				"type":        "string",
				"description": "Skill name or slug to activate",
			},
			"params": map[string]any{
				"type":        "object",
				"description": "Optional skill-specific parameters",
			},
		},
		"required": []string{"name"},
	}
}

func (t *UseSkillTool) Execute(ctx context.Context, args map[string]any) *Result {
	name, _ := args["name"].(string)
	if name == "" {
		return ErrorResult("name parameter is required")
	}
	if t.loader == nil {
		return ErrorResult("skill loader is not configured")
	}

	info, ok := t.findSkill(ctx, name)
	if !ok {
		return ErrorResult(fmt.Sprintf("skill %q not found", name))
	}
	if !t.canAccess(ctx, info) {
		return ErrorResult(fmt.Sprintf("skill %q is not accessible to this agent", name))
	}

	slog.Info("skill.activated", "skill", name)

	content, ok := t.loader.LoadSkill(ctx, info.Slug)
	if !ok && info.Name != info.Slug {
		content, ok = t.loader.LoadSkill(ctx, info.Name)
	}
	if !ok {
		return ErrorResult(fmt.Sprintf("skill %q could not be loaded", name))
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Skill %q activated.\n\n## SKILL.md\n\n%s", info.Slug, strings.TrimSpace(content))
	for _, ref := range loadMarkdownReferences(info.BaseDir) {
		fmt.Fprintf(&b, "\n\n---\n\n## %s\n\n%s", ref.name, strings.TrimSpace(ref.content))
	}
	return NewResult(b.String())
}

func (t *UseSkillTool) findSkill(ctx context.Context, name string) (skills.Info, bool) {
	for _, info := range t.loader.ListSkills(ctx) {
		if info.Slug == name || info.Name == name ||
			strings.EqualFold(info.Slug, name) || strings.EqualFold(info.Name, name) {
			return info, true
		}
	}
	return skills.Info{}, false
}

func (t *UseSkillTool) canAccess(ctx context.Context, info skills.Info) bool {
	if t.skillAccess == nil || info.Source != "managed" {
		return true
	}
	agentID := store.AgentIDFromContext(ctx)
	if agentID == uuid.Nil {
		return true
	}
	accessible, err := t.skillAccess.ListAccessible(ctx, agentID, store.UserIDFromContext(ctx))
	if err != nil {
		slog.Warn("use_skill: failed to load accessible skills", "error", err)
		return true
	}
	for _, allowed := range accessible {
		if allowed.Slug == info.Slug || allowed.Name == info.Name {
			return true
		}
	}
	return false
}

type skillReference struct {
	name    string
	content string
}

func loadMarkdownReferences(baseDir string) []skillReference {
	if baseDir == "" {
		return nil
	}
	refDir := filepath.Join(baseDir, "references")
	entries, err := os.ReadDir(refDir)
	if err != nil {
		return nil
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	var refs []skillReference
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".md") {
			continue
		}
		path := filepath.Join(refDir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		refs = append(refs, skillReference{
			name:    filepath.ToSlash(filepath.Join("references", entry.Name())),
			content: string(data),
		})
	}
	return refs
}

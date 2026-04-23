-- Add chat_id to vault_documents for cross-chat isolation within isolated teams.
-- NULL = team-wide doc (shared mode or legacy); non-NULL = scoped to specific chat.
ALTER TABLE vault_documents ADD COLUMN IF NOT EXISTS chat_id TEXT;

-- Composite index for team + chat filtering (primary query pattern for isolated teams).
CREATE INDEX IF NOT EXISTS idx_vault_docs_team_chat
    ON vault_documents(team_id, chat_id)
    WHERE team_id IS NOT NULL;

-- Backfill chat_id for isolated teams. Two path layouts exist:
--   master tenant:     teams/<team_uuid>/<chat>/...
--   non-master tenant: tenants/<slug>/teams/<team_uuid>/<chat>/...
-- Chat segments starting with '.' (e.g. '.goclaw') are config dirs, not real chats — skip.
UPDATE vault_documents vd
SET chat_id = (regexp_match(vd.path, '^(?:tenants/[^/]+/)?teams/[^/]+/([^/]+)/'))[1]
FROM agent_teams t
WHERE vd.team_id = t.id
  AND (t.settings->>'workspace_scope' IS NULL OR t.settings->>'workspace_scope' != 'shared')
  AND vd.path ~ '^(?:tenants/[^/]+/)?teams/[^/]+/[^.][^/]*/';

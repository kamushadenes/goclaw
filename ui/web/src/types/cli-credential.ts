export interface SecureCLIBinary {
  id: string;
  binary_name: string;
  binary_path?: string;
  description: string;
  deny_args: string[];
  deny_verbose: string[];
  timeout_seconds: number;
  tips: string;
  is_global: boolean;
  enabled: boolean;
  created_by: string;
  created_at: string;
  updated_at: string;
  /** Env variable names only (no values); from API for edit form */
  env_keys?: string[];
  /**
   * Agent grants summary for row chips (Phase 4 API field).
   * Absent on older API versions — capability-probe: skip rendering if undefined.
   */
  agent_grants_summary?: AgentGrantSummary[];
}

export interface CLIPresetEnvVar {
  name: string;
  desc: string;
  is_file?: boolean;
  optional?: boolean;
}

export interface CLIPreset {
  binary_name: string;
  description: string;
  env_vars: CLIPresetEnvVar[];
  deny_args: string[];
  deny_verbose: string[];
  timeout: number;
  tips: string;
}

export interface CLICredentialInput {
  preset?: string;
  binary_name: string;
  binary_path?: string;
  description?: string;
  deny_args?: string[];
  deny_verbose?: string[];
  timeout_seconds?: number;
  tips?: string;
  is_global?: boolean;
  enabled?: boolean;
  env?: Record<string, string>;
}

/** Per-agent grant with optional setting overrides */
export interface CLIAgentGrant {
  id: string;
  binary_id: string;
  agent_id: string;
  deny_args: string[] | null;
  deny_verbose: string[] | null;
  timeout_seconds: number | null;
  tips: string | null;
  enabled: boolean;
  /** Whether this grant has an env override (keys present, values encrypted) */
  env_set?: boolean;
  /** Env variable names only (no values); populated when env_set=true */
  env_keys?: string[];
  created_at: string;
  updated_at: string;
}

export interface CLIAgentGrantInput {
  agent_id: string;
  deny_args?: string[] | null;
  deny_verbose?: string[] | null;
  timeout_seconds?: number | null;
  tips?: string | null;
  enabled?: boolean;
  /**
   * env_vars in PUT body:
   *   absent / undefined  -> keep existing (omit from payload)
   *   null                -> clear override (fall back to binary defaults)
   *   Record<string,string> -> replace override
   */
  env_vars?: Record<string, string> | null;
}

/** Summary of a single grant shown in the table row chips (Phase 4 API field). */
export interface AgentGrantSummary {
  grant_id: string;
  agent_id: string;
  agent_key: string;
  name: string;
  enabled: boolean;
  env_set: boolean;
}

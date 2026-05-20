export type Action = 'allow' | 'deny' | 'escalate'
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type Phase = 1 | 2 | 3

export interface AnalyzedPath {
  path: string
  is_critical: boolean
  is_sensitive: boolean
  in_project: boolean
  risk_score: number
}

export interface AnalyzedHost {
  host: string
  is_external: boolean
  is_known_malicious: boolean
  risk_score: number
}

export interface DLPHit {
  pattern: string
  matched: string
  is_test_data: boolean
}

export interface SignalBundle {
  tool_class: { category: string; score: number }
  command: { verbs: string[]; max_danger: number; wrappers: string[] }
  path: { paths: AnalyzedPath[]; has_critical: boolean; has_sensitive: boolean; all_in_project: boolean; max_risk: number }
  network: { hosts: AnalyzedHost[]; has_data_flag: boolean; score: number }
  dlp: { hits: DLPHit[]; has_hit: boolean; all_test: boolean; score: number }
  evasion: { encoding: boolean; recursion: number; score: number }
  ml_score: number
}

export interface Span {
  name: string
  start_us: number
  duration_us: number
  phase: Phase
  result?: 'miss' | 'match' | 'skip'
  metadata?: Record<string, unknown>
}

export interface EvalStep {
  rule: string
  priority: number
  action: Action
  result: 'match' | 'skip'
  condition?: string
  latency_us?: number
}

export interface PolicySource {
  file: string
  line: number
  snippet: string
  condition: string
}

export interface BehavioralContext {
  retry_after_deny: boolean
  sequence_matches: string[]
  baseline_deviation: number
  risk_trend: number
  recent_denies: number
}

export interface LLMContext {
  intent: string
  confidence: number
  reasoning: string
  model: string
  latency_ms: number
}

export interface AegisEvent {
  id: string
  time: string
  agent_id: string
  session_id: string
  tool: string
  raw_command: string
  normalized_cmd: string
  args_json: Record<string, unknown>
  cwd: string
  action: Action
  rule: string
  severity: Severity
  confidence: number
  composite_score: number
  phase: Phase
  latency_us: number
  signals: SignalBundle
  trace: { spans: Span[]; total_us: number }
  eval_chain: EvalStep[]
  policy_source: PolicySource
  behavioral?: BehavioralContext
  llm?: LLMContext
  related_event_ids: string[]
  session_position: number
}

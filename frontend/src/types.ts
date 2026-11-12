export type Any = any;
export type Role = 'admin' | 'analyst' | 'viewer';
export interface Me { user: string; role: Role }
export interface Step { key: string; label: string; agent: string; status: 'pending' | 'running' | 'done' | 'failed' | 'skipped'; note?: string }
export interface IncidentSummary {
  id: string; title: string; severity: string; priority: string; riskScore: number; state: string; status: string; origin: string;
  createdAt: string; categories: string[]; workflow: Step[]; actions: number; tasks: { done: number; total: number }; pendingApprovals: number; alerts: number;
}
export interface Approval { incidentId: string; action: { id: string; description: string; reason: string; tier: string; ifNo?: string; type?: string } }
export interface EventT { id: string; ts: string; source: string; type: string; origin: string; user?: string; host?: string; ip?: string; geo?: string; resource?: string; domain?: string; count?: number; bytes?: number; scenarioId?: string }
export interface AgentStat { runs: number; failures: number; state: string; current?: string; lastMs?: number }
export interface Scenario { id: string; name: string; icon: string; blurb: string }
export interface AgentMsg { from: string; to: string; type: string; ts: string; payload: Any }
export interface AppState {
  metrics: Any; incidents: IncidentSummary[]; agents: Record<string, AgentStat>; messages: AgentMsg[]; scenarios: Scenario[]; integrations: Record<string, string>;
  settings: Any; approvals: Approval[]; events: EventT[]; assets: Any; analytics: Any; audit: Any[]; ops?: Any; autonomy: Any; connectors: Any; mode: string; manual?: Any[]; learning?: Any; suppressions?: Any[];
}

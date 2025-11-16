/**
 * API client for communication with the threat hunting analysis engine.
 */

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

export interface AnalysisResult {
  total_events: number;
  total_sessions: number;
  suspicious_sessions: number;
  sessions: Session[];
}

export interface Session {
  session_id: string;
  principal: string;
  risk_score: number;
  event_count: number;
  start_time: string;
  end_time: string;
  mitre_techniques: string[];
  kill_chain_stages: string[];
  iocs: IOCs;
  narrative: string;
  response_plan: ResponsePlan;
}

export interface IOCs {
  ip_addresses: IOC[];
  principals: IOC[];
  commands: IOC[];
  api_keys: IOC[];
  domains: IOC[];
}

export interface IOC {
  value: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  context?: string;
}

export interface ResponsePlan {
  immediate_actions: string[];
  containment: string[];
  eradication: string[];
  recovery: string[];
  timeline_estimate: string;
}

export interface Scenario {
  name: string;
  description: string;
  duration_hours: number;
  status?: 'running' | 'completed' | 'failed';
}

export class APIClient {
  private baseURL: string;
  private apiKey?: string;

  constructor(baseURL: string = API_BASE_URL, apiKey?: string) {
    this.baseURL = baseURL;
    this.apiKey = apiKey;
  }

  private async request<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<T> {
    const headers: HeadersInit = {
      'Content-Type': 'application/json',
      ...options.headers,
    };

    if (this.apiKey) {
      headers['X-API-Key'] = this.apiKey;
    }

    const response = await fetch(`${this.baseURL}${endpoint}`, {
      ...options,
      headers,
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({ detail: response.statusText }));
      throw new Error(error.detail || `Request failed: ${response.status}`);
    }

    return response.json();
  }

  // Scenario Management
  async listScenarios(): Promise<{ scenarios: string[] }> {
    return this.request('/scenarios');
  }

  async generateScenario(
    scenarioName: string,
    options?: {
      account_id?: string;
      region?: string;
      add_noise?: boolean;
    }
  ): Promise<{ status: string; scenario_name: string; output_dir: string }> {
    return this.request(`/scenarios/${scenarioName}/generate`, {
      method: 'POST',
      body: JSON.stringify(options || {}),
    });
  }

  async analyzeScenario(scenarioName: string): Promise<AnalysisResult> {
    return this.request(`/scenarios/${scenarioName}/analyze`, {
      method: 'POST',
    });
  }

  async deleteScenario(scenarioName: string): Promise<{ status: string }> {
    return this.request(`/scenarios/${scenarioName}`, {
      method: 'DELETE',
    });
  }

  // File Upload & Analysis
  async uploadAndAnalyze(file: File): Promise<AnalysisResult> {
    const formData = new FormData();
    formData.append('file', file);

    const headers: HeadersInit = {};
    if (this.apiKey) {
      headers['X-API-Key'] = this.apiKey;
    }

    const response = await fetch(`${this.baseURL}/analyze/upload`, {
      method: 'POST',
      headers,
      body: formData,
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({ detail: response.statusText }));
      throw new Error(error.detail || `Upload failed: ${response.status}`);
    }

    return response.json();
  }

  // Database Queries (if database is enabled)
  async listAnalyses(limit: number = 50, offset: number = 0): Promise<{
    total: number;
    analyses: Array<{
      id: number;
      scenario_name: string;
      num_events: number;
      num_suspicious_sessions: number;
      created_at: string;
    }>;
  }> {
    return this.request(`/database/analyses?limit=${limit}&offset=${offset}`);
  }

  async getAnalysisDetails(runId: number): Promise<{
    id: number;
    scenario_name: string;
    results: AnalysisResult;
    sessions: Session[];
  }> {
    return this.request(`/database/analyses/${runId}`);
  }

  async getSessionIOCs(sessionId: number): Promise<{
    session_id: number;
    iocs: Array<{
      id: number;
      type: string;
      value: string;
      severity: string;
      description: string;
    }>;
  }> {
    return this.request(`/database/sessions/${sessionId}/iocs`);
  }

  // Health Check
  async health(): Promise<{ status: string; timestamp: string }> {
    return this.request('/health');
  }

  // Statistics
  async stats(): Promise<{
    analyses_completed: number;
    scenarios_available: number;
    database_enabled: boolean;
  }> {
    return this.request('/stats');
  }
}

export const apiClient = new APIClient();

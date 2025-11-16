import React, { useState } from 'react';
import { AnalysisResult } from '../api/client';
import { TimelineView } from './TimelineView';
import { AttackGraphView } from './AttackGraphView';
import './AnalysisView.css';

interface AnalysisViewProps {
  analysis: AnalysisResult;
  onBack: () => void;
}

export const AnalysisView: React.FC<AnalysisViewProps> = ({ analysis, onBack }) => {
  const [selectedSessionIndex, setSelectedSessionIndex] = useState(0);

  if (!analysis.sessions || analysis.sessions.length === 0) {
    return (
      <div className="analysis-view">
        <button className="back-button" onClick={onBack}>
          ← Back to Scenarios
        </button>
        <div className="no-threats">
          <h2>No Threats Detected</h2>
          <p>The analysis completed successfully but found no suspicious activity.</p>
          <div className="stats">
            <div className="stat-card">
              <div className="stat-value">{analysis.total_events}</div>
              <div className="stat-label">Events Analyzed</div>
            </div>
            <div className="stat-card">
              <div className="stat-value">{analysis.total_sessions}</div>
              <div className="stat-label">Sessions Detected</div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  const session = analysis.sessions[selectedSessionIndex];

  return (
    <div className="analysis-view">
      <div className="analysis-header">
        <button className="back-button" onClick={onBack}>
          ← Back to Scenarios
        </button>

        <div className="analysis-summary">
          <h2>Threat Analysis Results</h2>
          <div className="summary-stats">
            <div className="stat-card">
              <div className="stat-value">{analysis.total_events}</div>
              <div className="stat-label">Events</div>
            </div>
            <div className="stat-card">
              <div className="stat-value">{analysis.suspicious_sessions}</div>
              <div className="stat-label">Threats</div>
            </div>
            <div className="stat-card">
              <div className="stat-value">
                {Math.max(...analysis.sessions.map((s) => s.risk_score * 100)).toFixed(0)}
                %
              </div>
              <div className="stat-label">Max Risk</div>
            </div>
          </div>
        </div>
      </div>

      {analysis.sessions.length > 1 && (
        <div className="session-selector">
          <h3>Detected Threats ({analysis.sessions.length})</h3>
          <div className="session-list">
            {analysis.sessions.map((s, index) => (
              <div
                key={index}
                className={`session-card ${index === selectedSessionIndex ? 'selected' : ''}`}
                onClick={() => setSelectedSessionIndex(index)}
              >
                <div className="session-info">
                  <div className="session-principal">
                    {s.principal.split('/').pop() || 'Unknown'}
                  </div>
                  <div className="session-stats">
                    <span>{s.event_count} events</span>
                    <span className={`risk-${s.risk_score > 0.7 ? 'high' : 'medium'}`}>
                      Risk: {(s.risk_score * 100).toFixed(0)}%
                    </span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="analysis-tabs">
        <div className="tabs">
          <button className="tab active">Overview</button>
          <button className="tab">IOCs</button>
          <button className="tab">Response Plan</button>
        </div>
      </div>

      <div className="analysis-content">
        <div className="content-grid">
          <div className="content-main">
            <TimelineView session={session} />
          </div>

          <div className="content-sidebar">
            <div className="narrative-panel">
              <h4>Threat Narrative</h4>
              <div className="narrative-content">
                {session.narrative || (
                  <>
                    <p>
                      <strong>Session ID:</strong> {session.session_id}
                    </p>
                    <p>
                      <strong>Principal:</strong> {session.principal}
                    </p>
                    <p>
                      <strong>Risk Score:</strong> {(session.risk_score * 100).toFixed(1)}%
                    </p>
                    <p>
                      <strong>Event Count:</strong> {session.event_count}
                    </p>
                    <p>
                      This session exhibits suspicious behavior across multiple MITRE
                      ATT&CK techniques, suggesting a coordinated attack.
                    </p>
                  </>
                )}
              </div>
            </div>

            {session.response_plan && (
              <div className="response-panel">
                <h4>Response Actions</h4>
                <div className="response-section">
                  <h5>Immediate Actions</h5>
                  <ul>
                    {session.response_plan.immediate_actions.map((action, i) => (
                      <li key={i}>{action}</li>
                    ))}
                  </ul>
                </div>
                <div className="response-section">
                  <h5>Containment</h5>
                  <ul>
                    {session.response_plan.containment.map((action, i) => (
                      <li key={i}>{action}</li>
                    ))}
                  </ul>
                </div>
              </div>
            )}
          </div>
        </div>

        <div className="graph-section">
          <AttackGraphView session={session} />
        </div>
      </div>
    </div>
  );
};

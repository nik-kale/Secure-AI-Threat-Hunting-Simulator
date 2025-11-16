import React from 'react';
import './App.css';

/**
 * SOC Dashboard Application
 *
 * This is the main entry point for the SOC Dashboard UI.
 * The UI provides visualization and exploration of threat hunting analysis results.
 *
 * Key Features:
 * - Timeline visualization of attack progression
 * - Attack graph showing entity relationships
 * - MITRE ATT&CK technique coverage
 * - IOC tables with contextual information
 * - Threat narrative display
 * - Response plan recommendations
 */

function App() {
  return (
    <div className="App">
      <header className="App-header">
        <h1>AI Threat Hunting Simulator</h1>
        <h2>SOC Dashboard</h2>
      </header>

      <main className="App-main">
        <div className="dashboard-container">
          <section className="welcome-section">
            <h3>Welcome to the SOC Dashboard</h3>
            <p>
              This dashboard provides interactive visualization and analysis of
              synthetic cloud attack scenarios.
            </p>

            <div className="feature-grid">
              <div className="feature-card">
                <h4>📊 Timeline View</h4>
                <p>Visualize attack progression across the cyber kill chain</p>
              </div>

              <div className="feature-card">
                <h4>🔗 Attack Graph</h4>
                <p>Explore relationships between entities and resources</p>
              </div>

              <div className="feature-card">
                <h4>🎯 MITRE ATT&CK</h4>
                <p>View detected techniques mapped to the ATT&CK framework</p>
              </div>

              <div className="feature-card">
                <h4>🔍 IOC Analysis</h4>
                <p>Browse indicators of compromise with context</p>
              </div>

              <div className="feature-card">
                <h4>📝 Threat Narrative</h4>
                <p>Read AI-generated attack narratives and analysis</p>
              </div>

              <div className="feature-card">
                <h4>🚨 Response Plan</h4>
                <p>Review recommended incident response actions</p>
              </div>
            </div>

            <div className="quickstart">
              <h4>Quick Start</h4>
              <ol>
                <li>
                  Start the analysis engine API:
                  <code>python -m uvicorn analysis_engine.api.server:app</code>
                </li>
                <li>
                  Run a scenario:
                  <code>python cli/run_scenario.py --scenario iam_priv_escalation --output ./output/demo</code>
                </li>
                <li>
                  Access analysis results via the API or load pre-generated reports
                </li>
              </ol>

              <p className="note">
                <strong>Note:</strong> This is a skeleton UI structure. Implement the
                following components to complete the dashboard:
              </p>

              <ul className="implementation-list">
                <li><code>components/TimelineView.tsx</code> - Event timeline visualization</li>
                <li><code>components/AttackGraphView.tsx</code> - Entity relationship graph</li>
                <li><code>components/NarrativePanel.tsx</code> - Threat narrative display</li>
                <li><code>components/IocTable.tsx</code> - IOC listing and filtering</li>
                <li><code>components/ResponsePlanPanel.tsx</code> - IR plan display</li>
                <li><code>pages/ScenarioSelection.tsx</code> - Scenario browser</li>
                <li><code>pages/AnalysisView.tsx</code> - Main analysis dashboard</li>
                <li><code>api/client.ts</code> - API client for backend communication</li>
              </ul>
            </div>
          </section>
        </div>
      </main>

      <footer className="App-footer">
        <p>AI Threat Hunting Simulator v1.0 | Open Source | Educational Use</p>
      </footer>
    </div>
  );
}

export default App;

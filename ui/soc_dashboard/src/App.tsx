import React, { useState } from 'react';
import { ScenarioSelection } from './components/ScenarioSelection';
import { AnalysisView } from './components/AnalysisView';
import { AnalysisResult } from './api/client';
import './App.css';

/**
 * SOC Dashboard Application
 *
 * Main entry point for the AI Threat Hunting Simulator dashboard.
 * Provides interactive visualization and analysis of cloud attack scenarios.
 */

function App() {
  const [currentView, setCurrentView] = useState<'home' | 'analysis'>('home');
  const [analysisResults, setAnalysisResults] = useState<AnalysisResult | null>(null);
  const [selectedScenario, setSelectedScenario] = useState<string | null>(null);

  const handleScenarioSelect = (scenarioName: string) => {
    setSelectedScenario(scenarioName);
  };

  const handleAnalysisComplete = (results: AnalysisResult) => {
    setAnalysisResults(results);
    setCurrentView('analysis');
  };

  const handleBackToHome = () => {
    setCurrentView('home');
    setAnalysisResults(null);
    setSelectedScenario(null);
  };

  return (
    <div className="App">
      <header className="App-header">
        <div className="header-content">
          <div className="header-title">
            <h1>🛡️ AI Threat Hunting Simulator</h1>
            <p className="subtitle">SOC Dashboard for Cloud Attack Analysis</p>
          </div>
          {currentView === 'analysis' && selectedScenario && (
            <div className="header-breadcrumb">
              <span className="breadcrumb-item" onClick={handleBackToHome}>
                Scenarios
              </span>
              <span className="breadcrumb-separator">/</span>
              <span className="breadcrumb-item active">{selectedScenario}</span>
            </div>
          )}
        </div>
      </header>

      <main className="App-main">
        {currentView === 'home' && (
          <ScenarioSelection
            onScenarioSelect={handleScenarioSelect}
            onAnalysisComplete={handleAnalysisComplete}
          />
        )}

        {currentView === 'analysis' && analysisResults && (
          <AnalysisView analysis={analysisResults} onBack={handleBackToHome} />
        )}
      </main>

      <footer className="App-footer">
        <div className="footer-content">
          <p>
            AI Threat Hunting Simulator v3.0 | Open Source | Educational Use Only
          </p>
          <div className="footer-links">
            <a
              href="https://attack.mitre.org"
              target="_blank"
              rel="noopener noreferrer"
            >
              MITRE ATT&CK
            </a>
            <span>•</span>
            <a
              href="https://github.com/anthropics/claude-code"
              target="_blank"
              rel="noopener noreferrer"
            >
              GitHub
            </a>
            <span>•</span>
            <a href="/docs" target="_blank" rel="noopener noreferrer">
              Documentation
            </a>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default App;

import React, { useState, useEffect } from 'react';
import { apiClient, Scenario } from '../api/client';
import './ScenarioSelection.css';

interface ScenarioSelectionProps {
  onScenarioSelect: (scenarioName: string) => void;
  onAnalysisComplete: (results: any) => void;
}

const SCENARIO_METADATA: Record<string, Scenario> = {
  iam_priv_escalation: {
    name: 'IAM Privilege Escalation',
    description: 'PassRole exploitation via Lambda function with backdoor creation',
    duration_hours: 1.0,
  },
  container_escape: {
    name: 'Container Breakout',
    description: 'Web exploit leading to container escape and cryptominer deployment',
    duration_hours: 0.67,
  },
  cred_stuffing: {
    name: 'Credential Stuffing',
    description: 'Distributed botnet credential stuffing attack',
    duration_hours: 0.33,
  },
  lateral_movement: {
    name: 'Lateral Movement',
    description: 'Multi-account AssumeRole chain attack across dev/staging/production',
    duration_hours: 1.5,
  },
  data_exfiltration: {
    name: 'Data Exfiltration',
    description: 'S3 enumeration, data copy to external bucket, CloudTrail deletion',
    duration_hours: 0.67,
  },
  supply_chain: {
    name: 'Supply Chain Attack',
    description: 'CI/CD compromise, malicious Lambda layer injection',
    duration_hours: 1.83,
  },
};

export const ScenarioSelection: React.FC<ScenarioSelectionProps> = ({
  onScenarioSelect,
  onAnalysisComplete,
}) => {
  const [scenarios, setScenarios] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [generating, setGenerating] = useState<string | null>(null);
  const [analyzing, setAnalyzing] = useState<string | null>(null);

  useEffect(() => {
    loadScenarios();
  }, []);

  const loadScenarios = async () => {
    try {
      setLoading(true);
      const response = await apiClient.listScenarios();
      setScenarios(response.scenarios);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load scenarios');
    } finally {
      setLoading(false);
    }
  };

  const handleGenerateAndAnalyze = async (scenarioName: string) => {
    try {
      setError(null);
      setGenerating(scenarioName);
      onScenarioSelect(scenarioName);

      // Generate synthetic telemetry
      await apiClient.generateScenario(scenarioName, {
        add_noise: true,
      });

      setGenerating(null);
      setAnalyzing(scenarioName);

      // Run analysis
      const results = await apiClient.analyzeScenario(scenarioName);

      setAnalyzing(null);
      onAnalysisComplete(results);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to generate/analyze scenario');
      setGenerating(null);
      setAnalyzing(null);
    }
  };

  const handleDelete = async (scenarioName: string, event: React.MouseEvent) => {
    event.stopPropagation();

    if (!window.confirm(`Delete scenario "${scenarioName}"?`)) {
      return;
    }

    try {
      await apiClient.deleteScenario(scenarioName);
      await loadScenarios();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete scenario');
    }
  };

  if (loading) {
    return <div className="scenario-selection loading">Loading scenarios...</div>;
  }

  return (
    <div className="scenario-selection">
      <h2>Attack Scenarios</h2>

      {error && (
        <div className="error-banner">
          <strong>Error:</strong> {error}
          <button onClick={() => setError(null)}>×</button>
        </div>
      )}

      <div className="scenario-grid">
        {Object.entries(SCENARIO_METADATA).map(([key, scenario]) => {
          const isGenerating = generating === key;
          const isAnalyzing = analyzing === key;
          const isActive = isGenerating || isAnalyzing;

          return (
            <div
              key={key}
              className={`scenario-card ${isActive ? 'active' : ''}`}
              onClick={() => !isActive && handleGenerateAndAnalyze(key)}
            >
              <div className="scenario-header">
                <h3>{scenario.name}</h3>
                <span className="scenario-duration">
                  {scenario.duration_hours < 1
                    ? `${Math.round(scenario.duration_hours * 60)}min`
                    : `${scenario.duration_hours}h`}
                </span>
              </div>

              <p className="scenario-description">{scenario.description}</p>

              <div className="scenario-footer">
                {isGenerating && (
                  <div className="status generating">
                    <span className="spinner"></span>
                    Generating telemetry...
                  </div>
                )}
                {isAnalyzing && (
                  <div className="status analyzing">
                    <span className="spinner"></span>
                    Analyzing threats...
                  </div>
                )}
                {!isActive && (
                  <>
                    <button
                      className="btn-primary"
                      onClick={(e) => {
                        e.stopPropagation();
                        handleGenerateAndAnalyze(key);
                      }}
                    >
                      Run Scenario
                    </button>
                    {scenarios.includes(key) && (
                      <button
                        className="btn-danger"
                        onClick={(e) => handleDelete(key, e)}
                      >
                        Delete
                      </button>
                    )}
                  </>
                )}
              </div>
            </div>
          );
        })}
      </div>

      <div className="upload-section">
        <h3>Or Upload Custom Telemetry</h3>
        <input
          type="file"
          accept=".jsonl,.json"
          onChange={async (e) => {
            const file = e.target.files?.[0];
            if (file) {
              try {
                setLoading(true);
                const results = await apiClient.uploadAndAnalyze(file);
                onAnalysisComplete(results);
              } catch (err) {
                setError(err instanceof Error ? err.message : 'Upload failed');
              } finally {
                setLoading(false);
              }
            }
          }}
        />
      </div>
    </div>
  );
};

import React, { useMemo } from 'react';
import { Session } from '../api/client';
import './TimelineView.css';

interface TimelineViewProps {
  session: Session;
}

interface TimelineEvent {
  timestamp: Date;
  stage: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
}

const KILL_CHAIN_STAGES = [
  'reconnaissance',
  'weaponization',
  'delivery',
  'exploitation',
  'installation',
  'command_control',
  'actions_on_objectives',
];

const STAGE_COLORS: Record<string, string> = {
  reconnaissance: '#95a5a6',
  weaponization: '#3498db',
  delivery: '#9b59b6',
  exploitation: '#e67e22',
  installation: '#e74c3c',
  command_control: '#c0392b',
  actions_on_objectives: '#8e44ad',
};

export const TimelineView: React.FC<TimelineViewProps> = ({ session }) => {
  const timeline = useMemo(() => {
    // Parse events from session data (this would come from actual event data)
    const events: TimelineEvent[] = [];

    // Extract events from MITRE techniques
    session.mitre_techniques.forEach((technique, index) => {
      const stage = session.kill_chain_stages[index] || 'unknown';
      const baseTime = new Date(session.start_time);
      const eventTime = new Date(
        baseTime.getTime() + index * 5 * 60 * 1000 // 5 minutes apart
      );

      events.push({
        timestamp: eventTime,
        stage,
        description: `MITRE ${technique}`,
        severity: session.risk_score > 0.7 ? 'critical' : 'high',
      });
    });

    return events.sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());
  }, [session]);

  const formatTime = (date: Date): string => {
    return date.toLocaleTimeString('en-US', {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });
  };

  const formatDuration = (start: string, end: string): string => {
    const duration = new Date(end).getTime() - new Date(start).getTime();
    const minutes = Math.floor(duration / 60000);
    const seconds = Math.floor((duration % 60000) / 1000);
    return `${minutes}m ${seconds}s`;
  };

  return (
    <div className="timeline-view">
      <div className="timeline-header">
        <h3>Attack Timeline</h3>
        <div className="timeline-stats">
          <span className="stat">
            <strong>Duration:</strong>{' '}
            {formatDuration(session.start_time, session.end_time)}
          </span>
          <span className="stat">
            <strong>Events:</strong> {session.event_count}
          </span>
          <span className="stat">
            <strong>Risk Score:</strong>{' '}
            <span className={`risk-score risk-${session.risk_score > 0.7 ? 'high' : 'medium'}`}>
              {(session.risk_score * 100).toFixed(0)}%
            </span>
          </span>
        </div>
      </div>

      <div className="kill-chain-stages">
        {KILL_CHAIN_STAGES.map((stage) => {
          const isActive = session.kill_chain_stages.includes(stage);
          return (
            <div
              key={stage}
              className={`stage ${isActive ? 'active' : ''}`}
              style={{
                borderColor: isActive ? STAGE_COLORS[stage] : '#e0e0e0',
                background: isActive ? `${STAGE_COLORS[stage]}15` : '#f8f9fa',
              }}
            >
              <div className="stage-name">{stage.replace(/_/g, ' ')}</div>
            </div>
          );
        })}
      </div>

      <div className="timeline-container">
        <div className="timeline-line"></div>

        {timeline.map((event, index) => (
          <div key={index} className="timeline-event">
            <div
              className="timeline-marker"
              style={{ backgroundColor: STAGE_COLORS[event.stage] || '#95a5a6' }}
            ></div>

            <div className="timeline-content">
              <div className="event-time">{formatTime(event.timestamp)}</div>
              <div className="event-stage">{event.stage.replace(/_/g, ' ')}</div>
              <div className="event-description">{event.description}</div>
            </div>
          </div>
        ))}
      </div>

      <div className="timeline-summary">
        <h4>Attack Progression Summary</h4>
        <div className="mitre-techniques">
          <strong>MITRE ATT&CK Techniques:</strong>
          <div className="technique-tags">
            {session.mitre_techniques.map((technique) => (
              <span key={technique} className="technique-tag">
                {technique}
              </span>
            ))}
          </div>
        </div>

        {session.iocs && (
          <div className="iocs-summary">
            <strong>Indicators of Compromise:</strong>
            <ul>
              {session.iocs.ip_addresses?.slice(0, 3).map((ioc, i) => (
                <li key={i}>
                  <span className={`severity-${ioc.severity}`}>{ioc.severity}</span>
                  IP: {ioc.value}
                </li>
              ))}
              {session.iocs.principals?.slice(0, 3).map((ioc, i) => (
                <li key={i}>
                  <span className={`severity-${ioc.severity}`}>{ioc.severity}</span>
                  Principal: {ioc.value}
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </div>
  );
};

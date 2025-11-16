import React, { useEffect, useRef } from 'react';
import { Session } from '../api/client';
import './AttackGraphView.css';

interface AttackGraphViewProps {
  session: Session;
}

interface GraphNode {
  id: string;
  label: string;
  type: 'principal' | 'resource' | 'action' | 'ioc';
  severity?: string;
}

interface GraphEdge {
  from: string;
  to: string;
  label: string;
}

export const AttackGraphView: React.FC<AttackGraphViewProps> = ({ session }) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    const container = containerRef.current;
    if (!canvas || !container) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    // Set canvas size
    canvas.width = container.clientWidth;
    canvas.height = 600;

    // Build graph data from session
    const nodes: GraphNode[] = [];
    const edges: GraphEdge[] = [];

    // Add principal node
    nodes.push({
      id: 'principal',
      label: session.principal.split('/').pop() || 'Unknown',
      type: 'principal',
    });

    // Add MITRE techniques as action nodes
    session.mitre_techniques.forEach((technique, index) => {
      const nodeId = `technique-${index}`;
      nodes.push({
        id: nodeId,
        label: technique,
        type: 'action',
      });

      if (index === 0) {
        edges.push({
          from: 'principal',
          to: nodeId,
          label: 'executes',
        });
      } else {
        edges.push({
          from: `technique-${index - 1}`,
          to: nodeId,
          label: 'leads to',
        });
      }
    });

    // Add IOC nodes
    if (session.iocs) {
      session.iocs.ip_addresses?.slice(0, 3).forEach((ioc, index) => {
        const nodeId = `ip-${index}`;
        nodes.push({
          id: nodeId,
          label: ioc.value,
          type: 'ioc',
          severity: ioc.severity,
        });

        edges.push({
          from: 'principal',
          to: nodeId,
          label: 'connects from',
        });
      });
    }

    // Simple force-directed layout
    const nodePositions = new Map<string, { x: number; y: number }>();
    const centerX = canvas.width / 2;
    const centerY = canvas.height / 2;
    const radius = 200;

    // Position principal in center
    nodePositions.set('principal', { x: centerX, y: centerY });

    // Position techniques in a circle
    session.mitre_techniques.forEach((_, index) => {
      const angle = (index / session.mitre_techniques.length) * 2 * Math.PI;
      const x = centerX + radius * Math.cos(angle);
      const y = centerY + radius * Math.sin(angle);
      nodePositions.set(`technique-${index}`, { x, y });
    });

    // Position IOCs in outer circle
    const iocCount = session.iocs?.ip_addresses?.length || 0;
    for (let i = 0; i < Math.min(iocCount, 3); i++) {
      const angle = ((i / 3) * 2 * Math.PI) + Math.PI / 2;
      const x = centerX + (radius + 80) * Math.cos(angle);
      const y = centerY + (radius + 80) * Math.sin(angle);
      nodePositions.set(`ip-${i}`, { x, y });
    }

    // Draw edges
    ctx.strokeStyle = '#bdc3c7';
    ctx.lineWidth = 2;
    edges.forEach((edge) => {
      const from = nodePositions.get(edge.from);
      const to = nodePositions.get(edge.to);
      if (from && to) {
        ctx.beginPath();
        ctx.moveTo(from.x, from.y);
        ctx.lineTo(to.x, to.y);
        ctx.stroke();

        // Draw edge label
        ctx.fillStyle = '#7f8c8d';
        ctx.font = '11px sans-serif';
        const midX = (from.x + to.x) / 2;
        const midY = (from.y + to.y) / 2;
        ctx.fillText(edge.label, midX, midY - 5);
      }
    });

    // Draw nodes
    nodes.forEach((node) => {
      const pos = nodePositions.get(node.id);
      if (!pos) return;

      // Node circle
      const colors = {
        principal: '#3498db',
        resource: '#2ecc71',
        action: '#9b59b6',
        ioc: node.severity === 'critical' ? '#e74c3c' : '#f39c12',
      };

      ctx.fillStyle = colors[node.type];
      ctx.beginPath();
      ctx.arc(pos.x, pos.y, 30, 0, 2 * Math.PI);
      ctx.fill();

      // Node label
      ctx.fillStyle = 'white';
      ctx.font = 'bold 12px sans-serif';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText(node.label.substring(0, 10), pos.x, pos.y);

      // Type label below node
      ctx.fillStyle = '#2c3e50';
      ctx.font = '10px sans-serif';
      ctx.fillText(node.type, pos.x, pos.y + 50);
    });
  }, [session]);

  return (
    <div className="attack-graph-view" ref={containerRef}>
      <div className="graph-header">
        <h3>Attack Graph</h3>
        <div className="legend">
          <div className="legend-item">
            <div className="legend-color" style={{ background: '#3498db' }}></div>
            <span>Principal</span>
          </div>
          <div className="legend-item">
            <div className="legend-color" style={{ background: '#9b59b6' }}></div>
            <span>Action</span>
          </div>
          <div className="legend-item">
            <div className="legend-color" style={{ background: '#e74c3c' }}></div>
            <span>Critical IOC</span>
          </div>
        </div>
      </div>
      <canvas ref={canvasRef} />
      <div className="graph-info">
        <p>
          This graph visualizes the attack flow from the compromised principal through
          various MITRE ATT&CK techniques to indicators of compromise.
        </p>
      </div>
    </div>
  );
};

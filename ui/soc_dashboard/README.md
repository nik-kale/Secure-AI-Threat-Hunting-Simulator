# SOC Dashboard

Interactive dashboard for visualizing AI threat hunting analysis results.

## Quick Start

```bash
# Install dependencies
npm install

# Start development server
npm start

# Build for production
npm run build
```

## Features (To Be Implemented)

- **Timeline View**: Chronological visualization of attack events
- **Attack Graph**: Entity relationship visualization
- **MITRE ATT&CK Mapping**: Technique coverage heatmap
- **IOC Tables**: Searchable, filterable indicators
- **Threat Narratives**: AI-generated analysis display
- **Response Plans**: Incident response recommendations

## API Integration

The dashboard connects to the analysis engine API at `http://localhost:8000`.

Key endpoints:
- `GET /scenarios` - List available scenarios
- `GET /scenarios/{name}` - Get scenario analysis
- `POST /analyze/upload` - Upload and analyze telemetry

## Directory Structure

```
src/
├── components/        # Reusable UI components
├── pages/            # Page-level components
├── api/              # API client
├── utils/            # Utilities
└── App.tsx           # Main application
```

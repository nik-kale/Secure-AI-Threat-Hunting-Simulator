#!/bin/bash
# Clean output directories

echo "Cleaning output directories..."

rm -rf output/scenarios/*
rm -rf output/reports/*
rm -rf output/telemetry/*

echo "✓ Output directories cleaned"

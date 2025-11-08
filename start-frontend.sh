#!/bin/bash
cd frontend
if [ ! -d "node_modules" ]; then
    npm install --ignore-scripts
fi
npm run dev


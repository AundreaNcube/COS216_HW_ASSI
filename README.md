# COS216 Homework Assignment 

## Overview
This repository contains the WebSocket server implementation for the COS216 homework assignment.

## Quick Start Guide (Task 2)

### Prerequisites
- Node.js installed (v18+ recommended)
- npm installed

### package.json
''' {
  "name": "multi-user-server",
  "version": "1.0.0",
  "description": "WebSocket server for multi-user COS216 HA",
  "main": "src/server.js",
  "scripts": {
    "start": "node src/server.js",
    "test": "echo \"No tests implemented yet\" && exit 0"
  },
  "keywords": [
    "websocket",
    "nodejs",
    "server",
    "multi-user",
    "cos216"
  ],
  "author": "Amantle Keamogetse Temo (u23539764) and Aundrea Ncube (u22747363)",
  "license": "ISC",
  "dependencies": {
    "axios": "^1.9.0",
    "dotenv": "^16.5.0",
    "ws": "^8.18.1",
    "readline-sync": "^1.4.10",
    "async-mutex": "^0.5.0"
  }
} '''

## Then  run npm install

## Make sure to modify the.env file

### Starting the server : 
1.npm start
or
2.node src/server.js 4494

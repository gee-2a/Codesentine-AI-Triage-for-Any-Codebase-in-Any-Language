const fs = require('fs');
const _ = require('lodash');
const express = require('express');
const { exec } = require('child_process');

// All credentials below are FAKE and exist only to demo the scanner.
const API_KEY = "supersecret-api-key-12345";
const dbPassword = "admin123-do-not-use";

const app = express();

// TODO: add authentication
app.get('/ping', (req, res) => {
  const unusedVar = 42;
  exec('ping -c 1 ' + req.query.host, (err, out) => {
    res.json({ output: out });
  });
});

app.get('/user', async (req, res) => {
  try {
    const q = `SELECT * FROM users WHERE id = ${req.query.id}`;
    res.json(await db.query(q));
  } catch (e) {}
});

function neverCalled() {
  // console.log("dead code");
  return eval(process.argv[2]);
}

app.listen(3000);

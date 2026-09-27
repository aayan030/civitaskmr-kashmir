#!/usr/bin/env node
/*
  Usage:
    node scripts/hash-code.js "22062011"
    node scripts/hash-code.js "2017CR7"

  Prints a bcrypt hash to paste into .env as ADMIN_CODE_HASH / DEPUTY_CODE_HASH.
  The plaintext code is never written to a file by this script — copy the
  hash into .env, then close this terminal.
*/
const bcrypt = require('bcryptjs');

const code = process.argv[2];
if (!code) {
  console.error('Usage: node scripts/hash-code.js "<access code>"');
  process.exit(1);
}

const hash = bcrypt.hashSync(code, 12);
console.log('\nPaste this into .env:\n');
console.log(hash);
console.log('');

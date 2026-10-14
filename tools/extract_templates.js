const fs = require('fs');
const src = fs.readFileSync('/home/claude/gen-src/templates.js', 'utf8');
const m = src.replace(/^\s*const xrayTemplates\s*=\s*/, '').replace(/;\s*$/, '');
const list = eval('(' + m + ')');
console.log(JSON.stringify(list));

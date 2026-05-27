'use strict';
// Shared validators used by both the running server and the offline test harness.

module.exports = {
  luhn(s) {
    const d = s.replace(/[^0-9]/g, '');
    if (d.length < 13 || d.length > 19) return false;
    let sum = 0; let alt = false;
    for (let i = d.length - 1; i >= 0; i--) {
      let n = parseInt(d[i], 10);
      if (alt) { n *= 2; if (n > 9) n -= 9; }
      sum += n; alt = !alt;
    }
    return sum % 10 === 0;
  },
  tckn(s) {
    if (!/^\d{11}$/.test(s)) return false;
    const d = s.split('').map(Number);
    if (d[0] === 0) return false;
    const oddSum = d[0] + d[2] + d[4] + d[6] + d[8];
    const evenSum = d[1] + d[3] + d[5] + d[7];
    const c10 = ((oddSum * 7) - evenSum) % 10;
    const c11 = (oddSum + evenSum + d[9]) % 10;
    return ((c10 + 10) % 10) === d[9] && c11 === d[10];
  },
  iban_mod97(s) {
    const c = s.replace(/\s+/g, '').toUpperCase();
    if (c.length < 15 || c.length > 34) return false;
    const re = c.slice(4) + c.slice(0, 4);
    let num = '';
    for (const ch of re) {
      const code = ch.charCodeAt(0);
      if (code >= 48 && code <= 57) num += ch;
      else if (code >= 65 && code <= 90) num += (code - 55).toString();
      else return false;
    }
    let rem = 0;
    for (const ch of num) rem = (rem * 10 + parseInt(ch, 10)) % 97;
    return rem === 1;
  },
};

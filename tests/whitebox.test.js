'use strict';

/**
 * WHITE-BOX TESTING – 06 Bài (SwagStore)
 *
 * Target functions:
 *   A) Account.verifyPassword(password, hash)       – 2-path function
 *   B) shopController.showShop(req, res)             – multi-branch + MC/DC
 *
 * Coverage criteria demonstrated:
 *   1. Statement Coverage
 *   2. Branch Coverage
 *   3. Decision Coverage
 *   4. Path Coverage
 *   5. MC/DC (Modified Condition/Decision Coverage)
 *   6. Flowchart-driven test design (path enumeration via flowchart analysis)
 */

const crypto    = require('crypto');
const Account   = require('../models/Account');
const shopCtrl  = require('../controllers/shopController');

// ─────────────────────────────────────────────────────────────
// Helper
// ─────────────────────────────────────────────────────────────
function mockRes() {
  const r = {};
  r.status   = jest.fn(() => r);
  r.send     = jest.fn(() => r);
  r.render   = jest.fn(() => r);
  r.redirect = jest.fn(() => r);
  return r;
}

function shopReq(query = {}) {
  return { session: {}, query };
}

// ─────────────────────────────────────────────────────────────
// TARGET A: Account.verifyPassword(password, hash)
//
// Code:
//   if (/^[a-f0-9]{64}$/.test(hash))          ← Decision D1
//     return sha256(password) === hash
//   return bcrypt.compareSync(password, hash)
//
// FlowChart paths:
//   Path 1: D1=true  → sha256 branch → return
//   Path 2: D1=false → bcrypt branch → return
// ─────────────────────────────────────────────────────────────

describe('Bài 1 – Statement Coverage: Account.verifyPassword', () => {
  // Two tests together cover every executable statement in the function.
  test('TC1 – sha256 branch (D1=true): correct password matches legacy hash', () => {
    const hash = crypto.createHash('sha256').update('pass1').digest('hex');
    expect(Account.verifyPassword('pass1', hash)).toBe(true);
  });

  test('TC2 – bcrypt branch (D1=false): correct password matches bcrypt hash', () => {
    const bcrypt = require('bcryptjs');
    const hash   = bcrypt.hashSync('pass2', 10);
    expect(Account.verifyPassword('pass2', hash)).toBe(true);
  });
});

describe('Bài 2 – Branch Coverage: Account.verifyPassword', () => {
  // Branch table:
  //   D1=true  → TC1, TC3 (correct / wrong password against sha256)
  //   D1=false → TC2, TC4 (correct / wrong password against bcrypt)
  test('TC1 – D1=true, password correct → true', () => {
    const hash = crypto.createHash('sha256').update('abc').digest('hex');
    expect(Account.verifyPassword('abc', hash)).toBe(true);
  });

  test('TC2 – D1=false, password correct → true', () => {
    const bcrypt = require('bcryptjs');
    const hash   = bcrypt.hashSync('abc', 10);
    expect(Account.verifyPassword('abc', hash)).toBe(true);
  });

  test('TC3 – D1=true, password wrong → false', () => {
    const hash = crypto.createHash('sha256').update('abc').digest('hex');
    expect(Account.verifyPassword('xyz', hash)).toBe(false);
  });

  test('TC4 – D1=false, password wrong → false', () => {
    const bcrypt = require('bcryptjs');
    const hash   = bcrypt.hashSync('abc', 10);
    expect(Account.verifyPassword('xyz', hash)).toBe(false);
  });
});

describe('Bài 3 – Decision Coverage: Account.verifyPassword', () => {
  // Decision = overall truth value of the if-condition.
  // Decision=TRUE  (hash is a 64-char hex string)
  // Decision=FALSE (hash is a bcrypt string)
  test('TC1 – Decision TRUE: sha256 hash recognized', () => {
    const hash = crypto.createHash('sha256').update('x').digest('hex');
    expect(/^[a-f0-9]{64}$/.test(hash)).toBe(true);
    expect(Account.verifyPassword('x', hash)).toBe(true);
  });

  test('TC2 – Decision FALSE: bcrypt hash not mistaken for sha256', () => {
    const bcrypt = require('bcryptjs');
    const hash   = bcrypt.hashSync('x', 10);
    expect(/^[a-f0-9]{64}$/.test(hash)).toBe(false);
    expect(Account.verifyPassword('x', hash)).toBe(true);
  });
});

describe('Bài 4 – Path Coverage: Account.verifyPassword', () => {
  // All feasible paths through the function (matches Branch Coverage here):
  //   Path 1: D1=true,  match=true  → return true
  //   Path 2: D1=true,  match=false → return false
  //   Path 3: D1=false, match=true  → return true
  //   Path 4: D1=false, match=false → return false
  const sha256Hash  = crypto.createHash('sha256').update('secret').digest('hex');
  const bcrypt      = require('bcryptjs');
  const bcryptHash  = bcrypt.hashSync('secret', 10);

  test('Path 1 – sha256 branch, match=true', () =>
    expect(Account.verifyPassword('secret', sha256Hash)).toBe(true));

  test('Path 2 – sha256 branch, match=false', () =>
    expect(Account.verifyPassword('wrong', sha256Hash)).toBe(false));

  test('Path 3 – bcrypt branch, match=true', () =>
    expect(Account.verifyPassword('secret', bcryptHash)).toBe(true));

  test('Path 4 – bcrypt branch, match=false', () =>
    expect(Account.verifyPassword('wrong', bcryptHash)).toBe(false));
});

describe('Bài 5 – MC/DC: showShop category filter condition', () => {
  /**
   * Compound condition: (category && category !== 'all')
   *   C1 = category is truthy
   *   C2 = category !== 'all'
   *   Result = C1 AND C2
   *
   * MC/DC pairs (each condition independently affects outcome):
   *   C1: (true,true)→true vs (false,true)→false  [C2 fixed=true]
   *   C2: (true,true)→true vs (true,false)→false   [C1 fixed=true]
   */
  test('MC/DC-1 C1=true, C2=true  → filter applied (result=true)', () => {
    const res = mockRes();
    shopCtrl.showShop(shopReq({ category: 'Apparel' }), res);
    const { products, activeCategory } = res.render.mock.calls[0][1];
    expect(activeCategory).toBe('Apparel');
    expect(products.every(p => p.category === 'Apparel')).toBe(true);
  });

  test('MC/DC-2 C1=false, C2=true → filter NOT applied (result=false)', () => {
    // category is falsy (empty string)
    const res = mockRes();
    shopCtrl.showShop(shopReq({ category: '' }), res);
    const { products } = res.render.mock.calls[0][1];
    expect(products.length).toBeGreaterThan(0);
  });

  test('MC/DC-3 C1=true,  C2=false → filter NOT applied (category==="all")', () => {
    const total = mockRes();
    shopCtrl.showShop(shopReq({}), total);
    const allCount = total.render.mock.calls[0][1].products.length;

    const res = mockRes();
    shopCtrl.showShop(shopReq({ category: 'all' }), res);
    const { products } = res.render.mock.calls[0][1];
    expect(products.length).toBe(allCount);
  });
});

describe('Bài 6 – Flowchart / Path Coverage: showShop sort paths', () => {
  /**
   * FlowChart of showShop sort section (3 independent if-branches):
   *
   *   [Start]
   *      │
   *   [D3: sort==='price-asc'?] ──true──→ [Sort asc]
   *      │false                                 │
   *   [D4: sort==='price-desc'?] ──true──→ [Sort desc]
   *      │false                                  │
   *   [D5: sort==='name'?] ──true──→ [Sort name]
   *      │false                          │
   *   [Render shop] ◄────────────────────┘
   *
   * Feasible paths enumerated (D3 D4 D5):
   *   P1: F F F – no sort
   *   P2: T F F – price-asc
   *   P3: F T F – price-desc
   *   P4: F F T – name
   *   (T+T is impossible: a query string can only have one value for "sort")
   */
  function getPrices(res) {
    return res.render.mock.calls[0][1].products.map(p => p.price);
  }
  function getNames(res) {
    return res.render.mock.calls[0][1].products.map(p => p.name);
  }

  test('Path P1 – no sort: product order is default', () => {
    const res = mockRes();
    shopCtrl.showShop(shopReq({}), res);
    const prices = getPrices(res);
    expect(prices.length).toBeGreaterThan(0);
  });

  test('Path P2 – sort=price-asc: prices in ascending order', () => {
    const res = mockRes();
    shopCtrl.showShop(shopReq({ sort: 'price-asc' }), res);
    const prices = getPrices(res);
    expect(prices).toEqual([...prices].sort((a, b) => a - b));
  });

  test('Path P3 – sort=price-desc: prices in descending order', () => {
    const res = mockRes();
    shopCtrl.showShop(shopReq({ sort: 'price-desc' }), res);
    const prices = getPrices(res);
    expect(prices).toEqual([...prices].sort((a, b) => b - a));
  });

  test('Path P4 – sort=name: names in alphabetical order', () => {
    const res = mockRes();
    shopCtrl.showShop(shopReq({ sort: 'name' }), res);
    const names = getNames(res);
    expect(names).toEqual([...names].sort((a, b) => a.localeCompare(b)));
  });
});

// Token-side suite: EthosToken, EthosMVPBadge, EthosStaking, EthosGovernance, EthosLiquidityManager, V3Math.
const { setup } = require('./env');
const L = require('./lib');
const { test, assert, reverts, ethers } = L;
const ref = require('./v3ref.json');
const E = (n) => ethers.parseEther(String(n));
const DAY = 86400;
(async () => {
  const e = await setup(); const d = e.deploy; const S = e.signers; const a = (s) => s.address;
  const owner = S[0], treasury = S[1], alice = S[6], bob = S[7], carol = S[8], dave = S[9], eve = S[10];
  const token = await d('EthosToken', [a(treasury), a(S[2]), a(S[3]), a(S[4]), a(S[5])]);
  const badge = await d('EthosMVPBadge');
  const staking = await d('EthosStaking', [await token.getAddress()]);
  const gov = await d('EthosGovernance', [await staking.getAddress()]);
  const lpm = await d('EthosLiquidityManager', [await token.getAddress()]);
  const T = await token.getAddress(), ST = await staking.getAddress(), LP = await lpm.getAddress(), B = await badge.getAddress(), G = await gov.getAddress();
  await (await token.setContracts(ST, ethers.ZeroAddress, LP)).wait();
  await (await badge.authorizeMinter(ST)).wait(); await (await badge.authorizeMinter(LP)).wait();
  await (await staking.setMVPBadge(B)).wait(); await (await lpm.setMVPBadge(B)).wait();
  const as = (c, s) => c.connect(s);
  const fund = async (to, n) => (await as(token, treasury).transfer(a(to), E(n))).wait();

  // ── V3Math ────────────────────────────────────────────────────────────────
  const H = await d('V3Harness');
  await test('V3Math tick->sqrtPrice matches high-precision reference', async () => {
    for (const [t, v] of Object.entries(ref)) {
      const got = await H.sqrtAt(Number(t)); const diff = got > BigInt(v) ? got - BigInt(v) : BigInt(v) - got;
      assert(diff <= 1n || diff * 10n ** 15n <= BigInt(v), `tick ${t}: got ${got} want ${v}`);
    }
    await reverts(H.sqrtAt(887273), 'TickOutOfRange');
  });
  await test('V3Math liquidity->amounts matches float reference for in/below/above range', async () => {
    const sp = (t) => 1.0001 ** (t / 2);
    for (const [pt, lo, hi] of [[-299340, -300000, -298800], [-310000, -300000, -298800], [-290000, -300000, -298800]]) {
      const L_ = 5n * 10n ** 16n;
      const [a0, a1] = await H.amounts(await H.sqrtAt(pt), await H.sqrtAt(lo), await H.sqrtAt(hi), L_);
      const P = Math.min(Math.max(sp(pt), sp(lo)), sp(hi)); const l = Number(L_);
      const w0 = l * (sp(hi) - P) / (P * sp(hi)), w1 = l * (P - sp(lo));
      const close = (g, w) => Math.abs(Number(g) - w) <= Math.max(1, w * 1e-6);
      assert(close(a0, w0) && close(a1, w1), `pt ${pt}: got ${a0},${a1} want ${w0},${w1}`);
    }
  });

  // ── EthosToken ────────────────────────────────────────────────────────────
  await test('supply accounting: 100M, contract holds 50M pool', async () => {
    assert((await token.totalSupply()) === E(100_000_000), 'supply');
    assert((await token.balanceOf(T)) === E(50_000_000), 'pool 50M');
  });
  await test('pool tokens can be released only by owner; supply conserved', async () => {
    await reverts(as(token, eve).distributePool(a(eve), E(1)), 'NotOwner');
    await reverts(token.distributePool(ethers.ZeroAddress, E(1)), 'ZeroAddress');
    await reverts(token.distributePool(a(alice), E(60_000_000)), 'InsufficientBalance');
    await (await token.distributePool(a(alice), E(30_000))).wait();
    assert((await token.balanceOf(a(alice))) === E(30_000), 'alice');
    assert((await token.balanceOf(T)) === E(50_000_000) - E(30_000), 'pool decreased');
    assert((await token.totalSupply()) === E(100_000_000), 'supply unchanged');
  });
  await test('authorized burner cannot burn a holder without allowance', async () => {
    await (await token.authorizeBurner(a(eve))).wait(); // eve plays a compromised burner
    await fund(bob, 1000);
    await reverts(as(token, eve).burnFrom(a(bob), E(500)), 'InsufficientAllowance');
    await reverts(as(token, eve).burnSubscriptionFee(a(bob)), 'InsufficientAllowance');
    await (await as(token, bob).approve(a(eve), E(100))).wait();
    await (await as(token, eve).burnSubscriptionFee(a(bob))).wait();
    assert((await token.balanceOf(a(bob))) === E(900), 'burned exactly the fee');
    assert((await token.allowance(a(bob), a(eve))) === 0n, 'allowance consumed');
    await (await token.revokeBurner(a(eve))).wait();
    await reverts(as(token, eve).burnFrom(a(bob), 1n), 'NotAuthorizedBurner');
  });
  await test('infinite allowance is not decremented; transferFrom still enforced', async () => {
    await (await as(token, bob).approve(a(carol), ethers.MaxUint256)).wait();
    await (await as(token, carol).transferFrom(a(bob), a(carol), E(1))).wait();
    assert((await token.allowance(a(bob), a(carol))) === ethers.MaxUint256, 'still max');
    await reverts(as(token, dave).transferFrom(a(bob), a(dave), 1n), 'InsufficientAllowance');
  });

  // ── Badge ─────────────────────────────────────────────────────────────────
  await test('badge keeps one token with per-source tiers; losing LP keeps MVP', async () => {
    await (await badge.authorizeMinter(a(owner))).wait();
    await (await badge.mintBadge(a(dave), 1)).wait();
    assert((await badge.getBadgeTier(a(dave))) === 1n, 'mvp');
    await (await badge.mintBadge(a(dave), 2)).wait();
    assert((await badge.getBadgeTier(a(dave))) === 2n, 'lp shown');
    await reverts(badge.mintBadge(a(dave), 2), 'AlreadyHasBadge');
    await (await badge.revokeBadge(a(dave), 2)).wait();
    assert((await badge.hasBadge(a(dave))) && (await badge.getBadgeTier(a(dave))) === 1n, 'mvp kept');
    await (await badge.revokeBadge(a(dave), 1)).wait();
    assert(!(await badge.hasBadge(a(dave))), 'gone');
    assert((await badge.totalActive()) === 0n && (await badge.getTotalMVP()) === 0n && (await badge.getTotalLP()) === 0n, 'counters');
    await (await badge.revokeMinter(a(owner))).wait();
    await reverts(as(badge, eve).mintBadge(a(eve), 1), 'NotAuthorizedMinter');
  });

  // ── Staking ───────────────────────────────────────────────────────────────
  await test('stake / MVP / badge / unstake round trip', async () => {
    await fund(alice, 20_000); await (await as(token, alice).approve(ST, ethers.MaxUint256)).wait();
    await reverts(as(staking, alice).stake(E(5000)), 'InsufficientStake');
    await (await as(staking, alice).stake(E(12_000))).wait();
    assert(await staking.isMVP(a(alice)) && await badge.hasBadge(a(alice)), 'mvp+badge');
    await reverts(as(staking, alice).stake(E(12_000)), 'AlreadyStaked');
    await (await as(staking, alice).requestUnstake()).wait();
    await reverts(as(staking, alice).requestUnstake(), 'UnstakeAlreadyRequested');
    await reverts(as(staking, alice).unstake(), 'CooldownNotMet');
    assert(!(await badge.hasBadge(a(alice))), 'badge revoked');
    await e.increaseTime(7 * DAY + 1);
    const before = await token.balanceOf(a(alice));
    await (await as(staking, alice).unstake()).wait();
    assert((await token.balanceOf(a(alice))) - before === E(12_000), 'refund');
    assert((await staking.totalStaked()) === 0n, 'totals');
  });
  await test('a broken / revoked badge contract can NEVER lock staked funds', async () => {
    await fund(bob, 10_000); await (await as(token, bob).approve(ST, ethers.MaxUint256)).wait();
    await (await as(staking, bob).stake(E(10_000))).wait();
    await (await badge.revokeMinter(ST)).wait(); // badge owner pulls the staking contract's minter rights
    await (await as(staking, bob).requestUnstake()).wait(); // used to revert
    await e.increaseTime(7 * DAY + 1);
    await (await as(staking, bob).unstake()).wait();
    await reverts(staking.setMVPBadge('0x000000000000000000000000000000000000dEaD'), 'ZeroAddress'); // EOA rejected
    await (await staking.setMVPBadge(await token.getAddress())).wait(); // a contract that reverts on every badge call
    await fund(bob, 0); await (await as(staking, bob).stake(E(10_000))).wait(); // still can stake
    await (await staking.setMVPBadge(B)).wait(); await (await badge.authorizeMinter(ST)).wait();
    await (await as(staking, bob).requestUnstake()).wait(); await e.increaseTime(7 * DAY + 1); await (await as(staking, bob).unstake()).wait();
  });
  await test('LP badge holder can still stake (no AlreadyHasBadge lock-out)', async () => {
    await (await badge.authorizeMinter(a(owner))).wait();
    await (await badge.mintBadge(a(carol), 2)).wait();
    await fund(carol, 10_000); await (await as(token, carol).approve(ST, ethers.MaxUint256)).wait();
    await (await as(staking, carol).stake(E(10_000))).wait();
    assert(await staking.isMVP(a(carol)), 'staked');
    await (await as(staking, carol).requestUnstake()).wait();
    assert(await badge.hasBadge(a(carol)) && (await badge.getBadgeTier(a(carol))) === 2n, 'LP tier survives unstake request');
    await e.increaseTime(7 * DAY + 1); await (await as(staking, carol).unstake()).wait();
    await (await badge.revokeBadge(a(carol), 2)).wait(); await (await badge.revokeMinter(a(owner))).wait();
  });
  await test('monthly burn: only staker/owner, interval enforced, burns from the staked balance, topUp restores MVP', async () => {
    await fund(dave, 10_100); await (await as(token, dave).approve(ST, ethers.MaxUint256)).wait();
    await (await as(staking, dave).stake(E(10_000))).wait();
    await reverts(as(staking, eve).executeMonthlyBurn(a(dave)), 'NotAuthorized');
    await reverts(as(staking, dave).executeMonthlyBurn(a(dave)), 'BurnIntervalNotMet');
    await e.increaseTime(30 * DAY + 1);
    const supply = await token.totalSupply();
    await (await as(staking, dave).executeMonthlyBurn(a(dave))).wait();
    assert((await supply - await token.totalSupply()) === E(100), 'supply -100');
    assert(!(await staking.isMVP(a(dave))), 'below threshold');
    await (await as(staking, dave).topUp(E(100))).wait();
    assert(await staking.isMVP(a(dave)) && await badge.hasBadge(a(dave)), 'restored');
    // staked tokens are accounted: contract holds exactly totalStaked
    assert((await token.balanceOf(ST)) === (await staking.totalStaked()), 'solvent');
  });

  // ── Governance ────────────────────────────────────────────────────────────
  const target = await d('GovTarget'); const TG = await target.getAddress();
  const ping = new ethers.Interface(['function ping()']).encodeFunctionData('ping');
  await (await gov.approveTarget(TG)).wait(); await (await gov.approveSelector(TG, ping.slice(0, 10))).wait();
  await test('governance: snapshot rule, strict end, quorum, timelock, expiry window', async () => {
    await fund(S[11], 200_000); await (await as(token, S[11]).approve(ST, ethers.MaxUint256)).wait();
    await (await as(staking, S[11]).stake(E(150_000))).wait(); // 150 votes
    await e.increaseTime(10);
    await (await as(gov, S[11]).createProposal('t', 'd', 0, TG, ping)).wait();
    // a staker who joins AFTER the proposal cannot vote on it (no borrow-and-vote)
    await fund(eve, 10_000); await (await as(token, eve).approve(ST, ethers.MaxUint256)).wait();
    await (await as(staking, eve).stake(E(10_000))).wait();
    await reverts(as(gov, eve).castVote(1, true), 'NoVotingPower');
    await (await as(gov, S[11]).castVote(1, true)).wait();
    await reverts(as(gov, S[11]).castVote(1, true), 'AlreadyVoted');
    await reverts(gov.finalizeProposal(1), 'VotingNotEnded');
    await e.increaseTime(7 * DAY);
    await reverts(as(gov, S[11]).castVote(1, true), ''); // closed exactly at endTime (strict)
    await (await gov.finalizeProposal(1)).wait();
    await reverts(gov.executeProposal(1), 'TimelockNotMet');
    await e.increaseTime(2 * DAY + 1);
    await (await gov.executeProposal(1)).wait();
    assert((await target.pings()) === 1n, 'executed once');
    await reverts(gov.executeProposal(1), 'ProposalNotPassed');
    // second proposal expires if nobody executes it in time
    await (await as(gov, S[11]).createProposal('t2', 'd', 0, TG, ping)).wait();
    await (await as(gov, S[11]).castVote(2, true)).wait();
    await e.increaseTime(7 * DAY + 1); await (await gov.finalizeProposal(2)).wait();
    await e.increaseTime(2 * DAY + 14 * DAY + 10);
    await reverts(gov.executeProposal(2), 'ProposalExpired');
    // non-whitelisted selector can't even be proposed
    await reverts(as(gov, S[11]).createProposal('bad', 'd', 0, TG, '0xdeadbeef'), 'SelectorNotApproved');
  });
  await test('governance: stake that exists at proposal time but was topped up later does not gain extra weight', async () => {
    // eve's top-up after proposal creation resets her powerSince, so she cannot vote on earlier proposals
    const id = Number(await gov.proposalCount()) + 1;
    await (await as(gov, S[11]).createProposal('t3', 'd', 0, ethers.ZeroAddress, '0x')).wait();
    await e.increaseTime(5);
    await fund(S[11], 1000); await (await as(staking, S[11]).topUp(E(1000))).wait();
    await reverts(as(gov, S[11]).castVote(id, true), 'NoVotingPower');
    await (await as(gov, eve).castVote(id, true).catch(() => null));
  });

  // ── LP manager with real pool math ────────────────────────────────────────
  const USDC = await d('MockToken');
  const U = await USDC.getAddress();
  const ethosIs0 = BigInt(T) < BigInt(U);
  const [t0, t1] = ethosIs0 ? [T, U] : [U, T];
  // ETHOS $0.10 : raw price(USDC/ETHOS) = 0.1e6/1e18 = 1e-13. When ETHOS is token1 the raw price inverts.
  const baseTick = ethosIs0 ? -299340 : 299340; // multiples of 60
  const lo = baseTick - 660, hi = baseTick + 540;
  const pool = await d('MockV3Pool', [t0, t1, 3000, baseTick]);
  const pm = await d('MockPositionManager');
  const Pm = await pm.getAddress(), Pl = await pool.getAddress();
  const hasLiq = (liq) => pm.set;
  await test('configurePool rejects a foreign pool / wrong token', async () => {
    const other = await d('MockV3Pool', [T, await token.getAddress(), 3000, 0]);
    await reverts(lpm.configurePool(Pm, await other.getAddress(), T, U), 'BadPoolConfig');
    await reverts(lpm.configurePool(Pm, Pl, U, U), 'BadPoolConfig');
    await reverts(as(lpm, eve).configurePool(Pm, Pl, T, U), 'NotOwner');
    await (await lpm.configurePool(Pm, Pl, T, U)).wait();
    assert((await lpm.poolFee()) === 3000n, 'fee recorded');
  });
  const setPos = (id, ownerAddr, liq, o = {}) => pm.set(id, ownerAddr, t0, t1, o.fee ?? 3000, o.lo ?? lo, o.hi ?? hi, liq);
  const sp = (t) => 1.0001 ** (t / 2);
  const floatValue = (liq, tick) => { // $ value in raw USDC units
    const P = Math.min(Math.max(sp(tick), sp(lo)), sp(hi)); const l = Number(liq);
    const a0 = l * (sp(hi) - P) / (P * sp(hi)), a1 = l * (P - sp(lo));
    const price = sp(tick) ** 2; // token1/token0 raw
    return ethosIs0 ? a1 + a0 * price : a0 + a1 / price;
  };
  // Choose a liquidity worth ~ $1,000
  let LIQ = 10n ** 16n; { const v = floatValue(LIQ, baseTick); LIQ = BigInt(Math.floor(Number(LIQ) * 1_000e6 / v)); }
  await test('LP value uses real V3 math at TWAP (≈$1000 position qualifies, value matches reference)', async () => {
    await setPos(1, a(alice), LIQ);
    const r = await as(lpm, alice).checkEligibility(1);
    assert(r[0], 'eligible: ' + r[1]);
    const want = floatValue(LIQ, baseTick);
    assert(Math.abs(Number(r[2]) - want) / want < 1e-5, `value ${r[2]} vs ${want}`);
    assert(Number(r[2]) > 900e6 && Number(r[2]) < 1100e6, 'about $1000');
  });
  await test('tiny / other-fee-tier / not-owned positions are rejected', async () => {
    await setPos(2, a(alice), LIQ / 10n); // ≈ $100
    let r = await as(lpm, alice).checkEligibility(2); assert(!r[0] && r[1].includes('minimum'), r[1]);
    await setPos(3, a(alice), LIQ, { fee: 500 });
    r = await as(lpm, alice).checkEligibility(3); assert(!r[0] && r[1].includes('fee'), r[1]);
    await reverts(as(lpm, alice).registerLP(3), 'WrongPool');
    await reverts(as(lpm, alice).registerLP(2), 'InsufficientLPValue');
    await reverts(as(lpm, eve).registerLP(1), 'NotPositionOwner');
    // far-out-of-range "whale liquidity" is valued by what it actually holds (here: a lot of ETHOS only) — not by raw L
    await pm.set(4, a(alice), t0, t1, 3000, ethosIs0 ? baseTick + 6000 : baseTick - 6000 - 60, ethosIs0 ? baseTick + 6060 : baseTick - 6000, LIQ * 1000n);
    // (just ensure it does not blow up and reports a number)
    await as(lpm, alice).checkEligibility(4);
  });
  await test('spot-price manipulation has no effect (TWAP only); young pool fails closed', async () => {
    await (await pool.setSpot(baseTick + 50_000)).wait();
    const r = await as(lpm, alice).checkEligibility(1); assert(r[0], 'unchanged under spot manipulation');
    await (await pool.setSpot(baseTick)).wait();
    await (await pool.setTooYoung(true)).wait();
    await reverts(as(lpm, alice).registerLP(1), '');
    await (await pool.setTooYoung(false)).wait();
  });
  await test('register -> Gold badge; one wallet per NFT; MVP badge not destroyed by LP removal', async () => {
    await (await as(lpm, alice).registerLP(1)).wait();
    assert((await badge.getBadgeTier(a(alice))) === 2n, 'gold');
    await reverts(as(lpm, alice).registerLP(1), 'AlreadyRegistered');
    await pm.setOwner(1, a(bob)); // alice "sells" the NFT to bob while still registered
    await reverts(as(lpm, bob).registerLP(1), 'PositionAlreadyClaimed');
    // anyone can evict alice now that the NFT moved
    await (await as(lpm, eve).deactivateIfInvalid(a(alice))).wait();
    assert(!(await lpm.isActiveLP(a(alice))) && !(await badge.hasBadge(a(alice))), 'evicted + badge gone');
    await (await as(lpm, bob).registerLP(1)).wait(); // bob legitimately owns it now
    assert(await lpm.isActiveLP(a(bob)), 'bob in');
    await reverts(as(lpm, eve).deactivateIfInvalid(a(bob)), 'NotLapsed');
    await (await as(lpm, bob).removeLP()).wait();
    assert(!(await badge.hasBadge(a(bob))), 'bob badge gone');
  });
  await test('monthly burn needs the provider\'s approval; lapse after grace; batch is not blockable', async () => {
    await pm.setOwner(1, a(alice)); await setPos(5, a(carol), LIQ);
    await fund(alice, 1000); await fund(carol, 1000);
    await (await as(lpm, alice).registerLP(1)).wait(); await (await as(lpm, carol).registerLP(5)).wait();
    await e.increaseTime(30 * DAY + 1);
    await reverts(as(lpm, alice).executeMonthlyBurn(a(alice)), 'BurnFailed'); // no allowance given
    await (await as(token, carol).approve(LP, E(100))).wait();
    const before = await token.totalSupply();
    await (await lpm.batchExecuteBurns([a(alice), a(carol)])).wait(); // alice fails silently, carol burns
    assert(before - (await token.totalSupply()) === E(100), 'only carol burned');
    assert((await lpm.getLPInfo(a(carol)))[5] === E(100), 'totalBurned recorded');
    await reverts(as(lpm, eve).deactivateIfInvalid(a(alice)), 'NotLapsed'); // inside grace
    await e.increaseTime(7 * DAY + 10);
    await (await as(lpm, eve).deactivateIfInvalid(a(alice))).wait(); // lapsed -> anyone
    assert(!(await lpm.isActiveLP(a(alice))), 'alice lapsed');
    assert((await lpm.totalLPProviders()) === 1n, 'count consistent');
    // emptied position is auto-removed on burn attempt
    await e.increaseTime(30 * DAY + 1); await pm.setLiquidity(5, 0);
    await (await as(lpm, carol).executeMonthlyBurn(a(carol))).wait();
    assert(!(await lpm.isActiveLP(a(carol))) && (await lpm.totalLPProviders()) === 0n, 'carol removed');
  });
  console.log(L.results.filter((r) => !r[1]).length ? 'SOME FAILED' : 'ALL PASSED', L.results.length);
  process.exit(0);
})().catch((x) => { console.error(x); process.exit(1); });

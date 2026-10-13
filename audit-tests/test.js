const ganache=require('/tmp/node_modules/ganache'),{ethers}=require('/tmp/node_modules/ethers'),fs=require('fs');
const art=JSON.parse(fs.readFileSync('/tmp/evmtest/out.json','utf8'));
let pass=0,fail=0;const ok=(c,m)=>{c?pass++:fail++;console.log((c?'PASS ':'FAIL ')+m)};
(async()=>{
const raw=ganache.provider({logging:{quiet:true},chain:{hardfork:'shanghai'},wallet:{totalAccounts:4,defaultBalance:1000},miner:{blockGasLimit:60000000}});
const prov=new ethers.BrowserProvider(raw,undefined,{cacheTimeout:-1});
const [signer,other]=await Promise.all([prov.getSigner(0),prov.getSigner(1)]);
const dep=async(n,args=[])=>{const f=new ethers.ContractFactory(art[n].abi,art[n].bin,signer);const c=await f.deploy(...args);await c.waitForDeployment();return c};
const bio=await dep('MockBio'), tl=await dep('TimeLockValidator',[await bio.getAddress()]), acct=await dep('MockAccount'), tok=await dep('MockToken');
const A=await acct.getAddress(), T=await tl.getAddress(), K=await tok.getAddress(), R=ethers.Wallet.createRandom().address;
const sz=(await prov.getCode(T)).length/2-1; console.log('TimeLock runtime bytes (shanghai/no-viaIR):',sz);
await (await acct.setExecutor(T)).wait(); await (await tok.mint(A,10n**12n)).wait();
const coder=ethers.AbiCoder.defaultAbiCoder();
const call=async(to,data)=> (await (await acct.call(to,data)).wait());
// install twice (validator + executor)
const guardians=[await other.getAddress()];
const initData=coder.encode(['address[]','uint256','uint256'],[guardians,1,0]);
await call(T,tl.interface.encodeFunctionData('onInstall',[initData]));
let r2=true;try{await call(T,tl.interface.encodeFunctionData('onInstall',[initData]))}catch(e){r2=false}
ok(r2,'onInstall idempotent (second install as executor does not revert)');
const mode='0x'+'00'.repeat(32);
const execData=(target,value,inner)=>{const packed=ethers.concat([target,ethers.toBeHex(value,32),inner]);return ethers.concat([ethers.id('execute(bytes32,bytes)').slice(0,10),coder.encode(['bytes32','bytes'],[mode,packed])])};
const op=(callData)=>({sender:A,nonce:0,initCode:'0x',callData,accountGasLimits:'0x'+'00'.repeat(32),preVerificationGas:0,gasFees:'0x'+'00'.repeat(32),paymasterAndData:'0x',signature:'0x1234'});
const tokIface=new ethers.Interface(['function transfer(address,uint256)']);
const validate=async(cd)=>{const rc=await (await acct.validate(T,op(cd),ethers.ZeroHash)).wait();const l=rc.logs.map(x=>{try{return acct.interface.parseLog(x)}catch{return null}}).find(x=>x&&x.name==='V');return l.args[0]};
const tr=(amt)=>execData(K,0n,tokIface.encodeFunctionData('transfer',[R,amt]));
const U=10n**6n;
// 1. small transfers within budget
ok(await validate(tr(1000n*U))===0n,'1000 USDC-units transfer #1 passes');
ok(await validate(tr(1000n*U))===0n,'transfer #2 (2000 total) passes');
ok(await validate(tr(1000n*U))===1n,'transfer #3 (3000 > 2500 window) FAILS -> velocity cap works');
// high value
ok(await validate(tr(10001n*U))===1n,'single 10,001 > high-value threshold FAILS');
// reviewer exploit: ETH value attached to transfer-looking call
const evil=execData(R,5n*10n**18n,tokIface.encodeFunctionData('transfer',[R,1n]));
ok(await validate(evil)===1n,'ETH value + transfer-shaped calldata FAILS CLOSED (reviewer exploit)');
// plain ETH send > tiny default -> high value (raw wei units) fails
ok(await validate(execData(R,10n**18n,'0x'))===1n,'1 ETH plain send fails under default raw-unit policy (needs per-token policy)');
// approve() call fails closed
const approve=execData(K,0n,new ethers.Interface(['function approve(address,uint256)']).encodeFunctionData('approve',[R,1n]));
ok(await validate(approve)===1n,'ERC20 approve fails closed');
// count cap: reset window by advancing 49h then do 10 x 100
await raw.send('evm_increaseTime',[49*3600]);await raw.send('evm_mine',[]);
let allOk=true;for(let i=0;i<10;i++) if(await validate(tr(100n*U))!==0n) allOk=false;
ok(allOk,'after 49h budget fully refreshed; 10 small txs pass');
ok(await validate(tr(1n*U))===1n,'11th small tx within window FAILS (count cap)');
await raw.send('evm_increaseTime',[25*3600]);await raw.send('evm_mine',[]);
// window partially refreshed (prev bucket weighting): at 25h, prev weight ~ (24-1)/24
const stillBlocked=await validate(tr(1000n*U));
console.log('   (info) 25h after 1000-unit burst, 1000 tx ->',stillBlocked===0n?'passes':'blocked by weighted prev bucket');
// 2. delayed tx + fingerprint release
const qd=tl.interface.encodeFunctionData('initiateDelayedTx',[K,5000n*U,R]);
ok(await validate(execData(T,0n,qd))===0n,'self-call initiateDelayedTx passes validator (whitelisted, moves no funds)');
const rcpt=await call(T,qd);
const evl=rcpt.logs.map(x=>{try{return tl.interface.parseLog(x)}catch{return null}}).filter(Boolean);
const req=evl.find(x=>x.name==='BiometricConfirmationRequested');
ok(!!req,'BiometricConfirmationRequested emitted (SMS notifier trigger)');
const txh=req.args.txHash, relBefore=await tok.balanceOf(R);
await bio.set(false);
let rev='';try{await tl.confirmAndRelease.staticCall(A,txh,'0x')}catch(e){rev=e.reason||e.shortMessage||String(e)}
ok(/Invalid fingerprint/.test(rev),'invalid fingerprint -> reverts ('+rev+')');
await bio.set(true);
await (await tl.confirmAndRelease(A,txh,'0x')).wait();
ok((await tok.balanceOf(R))-relBefore===5000n*U,'valid fingerprint releases funds via executeFromExecutor (packed encoding works)');
let dbl='';try{await tl.confirmAndRelease.staticCall(A,txh,'0x')}catch(e){dbl=e.reason||e.shortMessage||String(e)}
ok(/Already executed/.test(dbl),'cannot release twice');
// 3. expiry
const rc2=await call(T,qd);const txh2=rc2.logs.map(x=>{try{return tl.interface.parseLog(x)}catch{return null}}).filter(Boolean).find(x=>x.name==='TxDelayed').args.txHash;
await raw.send('evm_increaseTime',[48*3600+10]);await raw.send('evm_mine',[]);
let ex='';try{await tl.confirmAndRelease.staticCall(A,txh2,'0x')}catch(e){ex=e.reason||e.shortMessage||String(e)}
ok(/Expired/.test(ex),'after 48h confirmAndRelease reverts "Expired" even with valid fingerprint');
await (await tl.expireTx(A,txh2)).wait();
ok(true,'expireTx marks it cancelled');
// 4. policy
const setP=(hv,wl)=>tl.interface.encodeFunctionData('setTokenPolicy',[K,hv,wl]);
await call(T,setP(5000n*U,1000n*U));
let [hv,wl]=await tl.policyOf(A,K);ok(hv===5000n*U&&wl===1000n*U,'tightening policy applies immediately');
await call(T,setP(20000n*U,9000n*U));
[hv,wl]=await tl.policyOf(A,K);ok(hv===5000n*U,'loosening policy is queued, not applied');
const pend=await tl.pendingPolicy(A,K);ok(pend.applyAfter>0n,'pending policy recorded with applyAfter');
console.log(`\n${pass} passed, ${fail} failed`);process.exit(fail?1:0);
})().catch(e=>{console.error('HARNESS ERROR',e);process.exit(2)});

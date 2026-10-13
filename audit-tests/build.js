const solc=require('/tmp/node_modules/solc'),fs=require('fs'),path=require('path');
const root='/tmp/vault-audit';
const rm={'erc7579/':root+'/lib/erc7579-implementation/src/','account-abstraction/':root+'/lib/account-abstraction/contracts/','solady/':root+'/lib/solady/src/'};
function imp(p){for(const[k,v]of Object.entries(rm))if(p.startsWith(k)){try{return{contents:fs.readFileSync(v+p.slice(k.length),'utf8')}}catch(e){return{error:'nf'}}}try{return{contents:fs.readFileSync(path.join(root,p),'utf8')}}catch(e){return{error:'nf '+p}}}
const sources={'Mocks.sol':{content:fs.readFileSync('/tmp/evmtest/Mocks.sol','utf8')}};
const out=JSON.parse(solc.compile(JSON.stringify({language:'Solidity',sources,settings:{evmVersion:'shanghai',optimizer:{enabled:true,runs:200},outputSelection:{'*':{'*':['abi','evm.bytecode.object']}}}}),{import:imp}));
let bad=0;for(const e of out.errors||[])if(e.severity==='error'){bad=1;console.log(e.formattedMessage)}
if(!bad){const res={};for(const[f,cs]of Object.entries(out.contracts))for(const[n,c]of Object.entries(cs))if(c.evm.bytecode.object)res[n]={abi:c.abi,bin:'0x'+c.evm.bytecode.object};fs.writeFileSync('/tmp/evmtest/out.json',JSON.stringify(res));console.log('built',Object.keys(res).filter(n=>['TimeLockValidator','MockAccount','MockToken','MockBio'].includes(n)))}

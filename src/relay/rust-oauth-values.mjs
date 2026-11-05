// Flat graph codec: preserves own keys, UTF-16, undefined, aliases, holes and
// every IEEE-754 number. It performs no OAuth decision or JSON normalization.
const units = s => Array.from({length:s.length},(_,i)=>s.charCodeAt(i));
const string = units => { let s=''; for(let i=0;i<units.length;i+=16384)s+=String.fromCharCode(...units.slice(i,i+16384));return s; };
export function encodeValue(value) {
  const nodes=[],queue=[value],seen=new Map(); let undefinedId=value===undefined?0:null; if(value&&typeof value==='object')seen.set(value,0);
  const ref=value=>{if(value===undefined&&undefinedId!==null)return undefinedId;if(value&&typeof value==='object'&&seen.has(value))return seen.get(value);const id=queue.length;queue.push(value);if(value===undefined)undefinedId=id;if(value&&typeof value==='object')seen.set(value,id);return id;};
  for(let i=0;i<queue.length;i++) { const v=queue[i]; if(queue.length>13*1024*1024)throw Error('OAuth value resource limit.');
    if(v===undefined)nodes.push(['u']);else if(v===null)nodes.push(['n']);else if(typeof v==='boolean')nodes.push(['b',v]);else if(typeof v==='string')nodes.push(['s',units(v)]);else if(typeof v==='number'){const b=new ArrayBuffer(8),d=new DataView(b);d.setFloat64(0,v);nodes.push(['d',d.getBigUint64(0).toString(16).padStart(16,'0')]);}
    else if(Array.isArray(v)){const keys=Object.keys(v);if(keys.length===v.length&&keys.every((k,i)=>k===String(i)))nodes.push(['a',keys.map(k=>ref(v[k]))]);else nodes.push(['A',v.length,keys.map(k=>[units(k),ref(v[k])])]);}
    else if(typeof v==='object')nodes.push(['o',Object.keys(v).map(k=>[units(k),ref(v[k])])]);
    else throw TypeError('Unsupported OAuth helper value.');
  }return {root:0,nodes};
}
export function decodeValue(wire) {
  if(!wire||!Array.isArray(wire.nodes)||!Number.isInteger(wire.root)||wire.nodes.length>13*1024*1024)throw Error('Invalid OAuth value.');
  const values=wire.nodes.map(n=>{switch(n[0]){case'u':return undefined;case'n':return null;case'b':if(typeof n[1]!=='boolean')throw Error('Invalid Boolean.');return n[1];case's':if(!Array.isArray(n[1])||n[1].some(v=>!Number.isInteger(v)||v<0||v>65535))throw Error('Invalid UTF-16.');return string(n[1]);case'd':{if(!/^[0-9a-f]{16}$/.test(n[1]))throw Error('Invalid number.');const b=new ArrayBuffer(8),d=new DataView(b);d.setBigUint64(0,BigInt('0x'+n[1]));return d.getFloat64(0);}case'a':return [];case'A':if(!Number.isInteger(n[1])||n[1]<0||n[1]>4294967295)throw Error('Invalid array length.');return new Array(n[1]);case'o':return {};default:throw Error('Invalid value tag.');}});
  const get=i=>{if(!Number.isInteger(i)||i<0||i>=values.length)throw Error('Invalid value reference.');return values[i];};
  for(let i=0;i<wire.nodes.length;i++){const n=wire.nodes[i];if(n[0]==='a'){for(const id of n[1])values[i].push(get(id));}else if(n[0]==='o'||n[0]==='A'){for(const[k,id]of n[n[0]==='A'?2:1])Object.defineProperty(values[i],string(k),{value:get(id),enumerable:true,writable:true,configurable:true});}}
  return get(wire.root);
}

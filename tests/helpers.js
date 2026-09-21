import {createHmac} from 'node:crypto';
export function signed(user,token='test-token',date=Math.floor(Date.now()/1000)){
 const p=new URLSearchParams({auth_date:String(date),user:JSON.stringify(user)});
 const data=[...p.entries()].sort(([a],[b])=>a.localeCompare(b)).map(([k,v])=>`${k}=${v}`).join('\n');
 const key=createHmac('sha256','WebAppData').update(token).digest();p.set('hash',createHmac('sha256',key).update(data).digest('hex'));return p.toString();
}

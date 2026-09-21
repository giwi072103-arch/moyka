import { createPool, migrate } from './db.js';
import { createApp } from './app.js';
const db=createPool();
await migrate(db);
const app=createApp(db,process.env);
const server=app.listen(Number(process.env.PORT||3000),'0.0.0.0',()=>console.log('Wash server started'));
async function shutdown(){server.close(async()=>{await db.end();process.exit(0)});setTimeout(()=>process.exit(1),10000).unref();}
process.on('SIGTERM',shutdown);process.on('SIGINT',shutdown);

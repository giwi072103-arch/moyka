// Disposable local preview. It has no development-login bypass.
// This module is not used by the Docker CMD or Railway start command.
import {PGlite} from '@electric-sql/pglite';
import {migrate} from './db.js';
import {createApp} from './app.js';
const pg=new PGlite();
const query=(sql,args)=>sql.includes('pg_advisory_xact_lock')?Promise.resolve({rows:[]}):args?pg.query(sql,args):pg.exec(sql).then(results=>results.at(-1));
const db={query,connect:async()=>({query,release(){}})};
await migrate(db);
createApp(db,{APP_URL:'http://localhost:3000',NODE_ENV:'development'}).listen(3000,'0.0.0.0',()=>console.log('Disposable preview: http://localhost:3000'));

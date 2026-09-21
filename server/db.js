import pg from 'pg';
import { readFile } from 'node:fs/promises';
export async function migrate(db) {
  // Transactional schema migration + seed, guarded against simultaneous startup.
  const client = await db.connect();
  try {
    await client.query('BEGIN');
    await client.query('SELECT pg_advisory_xact_lock(872913)');
    await client.query(await readFile(new URL('./schema.sql', import.meta.url),'utf8'));
    const {rows} = await client.query('SELECT count(*)::int AS count FROM services');
    if (!rows[0].count) {
      const services = [
        ['Экспресс-мойка','Кузов, пена и бережная сушка','Кузов',35000,25],
        ['Комплексная мойка','Кузов, коврики, пылесос и протирка салона','Комплексы',70000,50],
        ['Уборка салона','Пылесос, панели, стёкла и коврики','Салон',40000,35],
        ['Глубокая химчистка','Тщательная очистка сидений и обивки','Детейлинг',350000,240],
        ['Защита воском','Защитный состав после мойки кузова','Кузов',100000,60],
        ['Полировка фар','Восстановление прозрачности фар','Детейлинг',120000,60]
      ];
      for(let i=0;i<services.length;i++) await client.query('INSERT INTO services(name,description,category,price,duration,sort_order) VALUES($1,$2,$3,$4,$5,$6)', [...services[i],i]);
    }
    await client.query('COMMIT');
  } catch(e) {await client.query('ROLLBACK');throw e;} finally {client.release();}
}
export function createPool() {
  if(!process.env.DATABASE_URL) throw new Error('DATABASE_URL is required');
  return new pg.Pool({connectionString:process.env.DATABASE_URL,max:10,connectionTimeoutMillis:10000,idleTimeoutMillis:30000});
}

import express from 'express';
import helmet from 'helmet';
import { rateLimit } from 'express-rate-limit';
import { z } from 'zod';
import { resolve } from 'node:path';
import { validateTelegram, newToken, hashToken, normalizePlate, validPlate, transitions, encryptCard, decryptCard } from './security.js';
const text = (max=200) => z.string().trim().min(1).max(max);
const id = z.coerce.number().int().positive().safe();
const phone = z.string().regex(/^\+998\d{9}$/, 'Телефон: +998 и 9 цифр');
const serviceSchema = z.object({name:text(100),description:text(500),category:text(40),price:z.number().int().min(0).max(100000000),duration:z.number().int().min(10).max(480),active:z.boolean().default(true)});
function fail(status,message){const e=new Error(message);e.status=status;throw e;}
export function createApp(db,env={}) {
 const app=express(); const production=env.NODE_ENV==='production';
 app.disable('x-powered-by'); app.set('trust proxy',Number(env.TRUST_PROXY_HOPS||1));
 app.use(helmet({contentSecurityPolicy:{directives:{defaultSrc:["'self'"],scriptSrc:["'self'",'https://telegram.org'],styleSrc:["'self'","'unsafe-inline'"],imgSrc:["'self'",'data:','blob:'],connectSrc:["'self'"],frameAncestors:["'self'",'https://web.telegram.org','https://*.telegram.org'],upgradeInsecureRequests:production?[]:null}},frameguard:false}));
 app.use('/api',rateLimit({windowMs:60000,limit:240,standardHeaders:'draft-8',legacyHeaders:false}));
 app.use(express.json({limit:'32kb'}));
 const q=async(sql,args=[]) => (await db.query(sql,args)).rows;
 const audit=async(actor,action,entity,details={})=>q('INSERT INTO audit(actor_id,action,entity_id,details) VALUES($1,$2,$3,$4)',[actor,action,String(entity),JSON.stringify(details)]);
 app.use('/api',(req,res,next)=>{res.set('Cache-Control','no-store');if(!['GET','HEAD','OPTIONS'].includes(req.method)&&req.get('origin')!==env.APP_URL) return res.status(403).json({error:'Недопустимый источник запроса'});next();});
 app.get('/api/health',async(req,res)=>{await q('SELECT 1');res.json({ok:true});});
 app.get('/api/catalog',async(req,res)=>{
  const [services,settings,team]=await Promise.all([q('SELECT * FROM services WHERE active=true ORDER BY sort_order,id'),q('SELECT * FROM settings WHERE id=1'),q(`SELECT w.user_id,w.full_name,w.available, EXISTS(SELECT 1 FROM orders o WHERE o.washer_id=w.user_id AND o.status IN ('accepted','washing')) AS busy FROM washers w JOIN users u ON u.id=w.user_id WHERE application_status='approved' AND u.blocked=false AND u.role='washer' ORDER BY w.full_name`)]);
  res.json({services,settings:settings[0],team,telegramConfigured:Boolean(env.BOT_TOKEN),cardsEnabled:/^[0-9a-f]{64}$/i.test(env.CARD_ENCRYPTION_KEY||'')});
 });
 app.post('/api/auth/telegram',rateLimit({windowMs:60000,limit:15}),async(req,res)=>{
  if(!env.BOT_TOKEN) fail(503,'Вход в Telegram ещё не настроен владельцем');
  let telegram;try {telegram=validateTelegram(req.body.initData,env.BOT_TOKEN);}catch{fail(401,'Откройте приложение заново через Telegram');}
  const admins=(env.ADMIN_TELEGRAM_IDS||'').split(',').map(s=>s.trim());
  const name=[telegram.first_name,telegram.last_name].filter(Boolean).join(' ').slice(0,200);
  const [user]=await q(`INSERT INTO users(telegram_id,name,role) VALUES($1,$2,$3) ON CONFLICT(telegram_id) DO UPDATE SET name=excluded.name RETURNING *`,[String(telegram.id),name,admins.includes(String(telegram.id))?'admin':'client']);
  if(user.blocked) fail(403,'Доступ ограничен администратором');
  // The environment allowlist is authoritative for owner privileges.
  if(admins.includes(user.telegram_id)&&user.role!=='admin')await q("UPDATE users SET role='admin' WHERE id=$1",[user.id]);
  if(!admins.includes(user.telegram_id)&&user.role==='admin')await q("UPDATE users SET role='client' WHERE id=$1",[user.id]);
  const token=newToken(); await q("DELETE FROM sessions WHERE expires_at<now() OR user_id=$1",[user.id]);
  await q("INSERT INTO sessions VALUES($1,$2,now()+interval '7 days')",[hashToken(token),user.id]);
  res.cookie('wash_session',token,{httpOnly:true,secure:production,sameSite:'lax',maxAge:604800000,path:'/'});res.json({ok:true,token});
 });
 app.use('/api',async(req,res,next)=>{
  const token=req.get('authorization')?.match(/^Bearer ([a-f0-9]{64})$/)?.[1] || (req.headers.cookie||'').split(';').map(v=>v.trim()).find(v=>v.startsWith('wash_session='))?.slice(13);
  if(!token||!/^[a-f0-9]{64}$/.test(token))return res.status(401).json({error:'Войдите через Telegram'});
  const [user]=await q('SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.expires_at>now()',[hashToken(token)]);
  if(!user||user.blocked)return res.status(401).json({error:'Сессия завершена. Откройте приложение через Telegram'});
  req.user=user;next();
 });
 const staff=(req,res,next)=>req.user.role==='washer'||req.user.role==='admin'?next():res.status(403).json({error:'Только для сотрудников'});
 const admin=(req,res,next)=>req.user.role==='admin'?next():res.status(403).json({error:'Только для администратора'});
 const orderAccess=async(req)=>{const [o]=await q('SELECT * FROM orders WHERE id=$1',[id.parse(req.params.id)]);if(!o)fail(404,'Заказ не найден');if(req.user.role!=='admin'&&String(o.user_id)!==String(req.user.id)&&String(o.washer_id)!==String(req.user.id))fail(403,'Нет доступа к заказу');return o;};
 app.post('/api/auth/logout',async(req,res)=>{await q('DELETE FROM sessions WHERE user_id=$1',[req.user.id]);res.clearCookie('wash_session',{path:'/'}).json({ok:true});});
 app.get('/api/me',async(req,res)=>{const [washer]=await q('SELECT user_id,full_name,phone,application_status,available,card_encrypted IS NOT NULL AS has_card FROM washers WHERE user_id=$1',[req.user.id]);res.json({user:req.user,washer:washer||null});});
 app.patch('/api/me',async(req,res)=>{const data=z.object({phone}).parse(req.body);await q('UPDATE users SET phone=$1 WHERE id=$2',[data.phone,req.user.id]);res.json({ok:true});});
 app.get('/api/cars',async(req,res)=>res.json(await q('SELECT id,brand,plate,photo IS NOT NULL AS has_photo FROM cars WHERE user_id=$1 ORDER BY id DESC',[req.user.id])));
 app.post('/api/cars',async(req,res)=>{const data=z.object({brand:text(80),plate:text(20).refine(validPlate,'Формат номера: 80 A 123 AA или 80 123 AAA')}).parse(req.body);const [car]=await q('INSERT INTO cars(user_id,brand,plate) VALUES($1,$2,$3) RETURNING id,brand,plate',[req.user.id,data.brand,normalizePlate(data.plate)]);res.status(201).json(car);});
 app.put('/api/cars/:id/photo',express.raw({type:['image/jpeg','image/png','image/webp'],limit:'2mb'}),async(req,res)=>{
  const carId=id.parse(req.params.id);const [car]=await q('SELECT id FROM cars WHERE id=$1 AND user_id=$2',[carId,req.user.id]);if(!car)fail(404,'Автомобиль не найден');
  const b=req.body,t=req.get('content-type'); if(!Buffer.isBuffer(b)||b.length<12)fail(400,'Выберите JPEG, PNG или WebP');
  const valid=(t==='image/jpeg'&&b[0]===255&&b[1]===216&&b[2]===255)||(t==='image/png'&&b.subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10])))||(t==='image/webp'&&b.toString('ascii',0,4)==='RIFF'&&b.toString('ascii',8,12)==='WEBP');
  if(!valid)fail(400,'Формат файла не соответствует изображению');await q('UPDATE cars SET photo=$1,photo_type=$2 WHERE id=$3',[b,t,carId]);res.json({ok:true});
 });
 app.get('/api/cars/:id/photo',async(req,res)=>{const [car]=await q(`SELECT photo,photo_type FROM cars c WHERE c.id=$1 AND (c.user_id=$2 OR $3='admin' OR EXISTS(SELECT 1 FROM orders o WHERE o.car_id=c.id AND o.washer_id=$2 AND o.status NOT IN ('completed','cancelled')))`,[id.parse(req.params.id),req.user.id,req.user.role]);if(!car?.photo)fail(404,'Фото не найдено');res.type(car.photo_type).send(car.photo);});
 app.post('/api/washer/apply',async(req,res)=>{
  const data=z.object({full_name:text(150),phone}).parse(req.body);if(req.user.role==='admin')fail(409,'Администратор уже имеет доступ к управлению');
  const [existing]=await q('SELECT application_status FROM washers WHERE user_id=$1',[req.user.id]);if(existing&&existing.application_status!=='rejected')fail(409,'Заявка уже подана');
  await q(`INSERT INTO washers(user_id,full_name,phone) VALUES($1,$2,$3) ON CONFLICT(user_id) DO UPDATE SET full_name=excluded.full_name,phone=excluded.phone,application_status='pending',available=false`,[req.user.id,data.full_name,data.phone]);res.status(201).json({ok:true});
 });
 app.patch('/api/washer/availability',staff,async(req,res)=>{const {available}=z.object({available:z.boolean()}).parse(req.body);const rows=await q("UPDATE washers SET available=$1 WHERE user_id=$2 AND application_status='approved' RETURNING user_id",[available,req.user.id]);if(!rows.length)fail(403,'Нет одобренного профиля мойщика');res.json({ok:true});});
 app.put('/api/washer/card',staff,async(req,res)=>{const {number}=z.object({number:z.string().regex(/^\d{16}$/)}).parse(req.body);if(!env.CARD_ENCRYPTION_KEY)fail(503,'Приём реквизитов ещё не настроен');await q('UPDATE washers SET card_encrypted=$1 WHERE user_id=$2',[encryptCard(number,env.CARD_ENCRYPTION_KEY),req.user.id]);res.json({ok:true});});
 app.get('/api/orders',async(req,res)=>{
  const scope=req.user.role==='admin'?'TRUE':req.user.role==='washer'?"(o.washer_id=$1 OR o.user_id=$1 OR o.status='queued')":'o.user_id=$1';
  const rows=await q(`SELECT o.*,c.brand,c.plate,c.photo IS NOT NULL AS has_photo,u.name AS client_name,w.full_name AS washer_name FROM orders o JOIN cars c ON c.id=o.car_id JOIN users u ON u.id=o.user_id LEFT JOIN washers w ON w.user_id=o.washer_id WHERE ${scope} ORDER BY o.created_at DESC LIMIT 200`,req.user.role==='admin'?[]:[req.user.id]);res.json(rows);
 });
 app.post('/api/orders',async(req,res)=>{
  const data=z.object({car_id:id,service_id:id,note:z.string().trim().max(500).default('')}).parse(req.body);
  if(!req.user.phone)fail(400,'Сначала сохраните номер телефона в профиле');
  const [order]=await q(`INSERT INTO orders(user_id,car_id,service_id,service_name,price,duration,note) SELECT $1,c.id,s.id,s.name,s.price,s.duration,$4 FROM cars c CROSS JOIN services s WHERE c.id=$2 AND c.user_id=$1 AND s.id=$3 AND s.active=true RETURNING *`,[req.user.id,data.car_id,data.service_id,data.note]);if(!order)fail(400,'Выберите свой автомобиль и доступную услугу');res.status(201).json(order);
 });
 app.patch('/api/orders/:id/status',async(req,res)=>{
  const data=z.object({status:z.enum(['accepted','washing','ready','completed','cancelled'])}).parse(req.body);
  const orderId=id.parse(req.params.id);const client=await db.connect();
  try{await client.query('BEGIN');const {rows:[o]}=await client.query('SELECT * FROM orders WHERE id=$1 FOR UPDATE',[orderId]);if(!o)fail(404,'Заказ не найден');
   const owner=String(o.user_id)===String(req.user.id),assigned=String(o.washer_id)===String(req.user.id),isAdmin=req.user.role==='admin';
   const claiming=req.user.role==='washer'&&o.status==='queued'&&data.status==='accepted';
   if(!isAdmin&&!claiming&&!(assigned&&req.user.role==='washer')&&!(owner&&o.status==='queued'&&data.status==='cancelled'))fail(403,'Недостаточно прав для смены статуса');
   if(!transitions[o.status].includes(data.status))fail(409,'Этот переход статуса недоступен');
   let washer=o.washer_id;
   if(claiming){const {rows:[w]}=await client.query("SELECT * FROM washers WHERE user_id=$1 AND application_status='approved' AND available=true FOR UPDATE",[req.user.id]);if(!w)fail(409,'Сначала включите приём заказов');washer=req.user.id;}
   if(data.status==='accepted'&&!washer)fail(400,'Заказ должен принять мойщик');
   const {rows:[updated]}=await client.query('UPDATE orders SET status=$1,washer_id=$2,updated_at=now() WHERE id=$3 RETURNING *',[data.status,washer,orderId]);
   await client.query('INSERT INTO audit(actor_id,action,entity_id,details) VALUES($1,$2,$3,$4)',[req.user.id,'order.status',String(orderId),JSON.stringify({from:o.status,to:data.status})]);await client.query('COMMIT');res.json(updated);
  }catch(e){await client.query('ROLLBACK');throw e;}finally{client.release();}
 });
 app.post('/api/orders/:id/review',async(req,res)=>{const o=await orderAccess(req);if(String(o.user_id)!==String(req.user.id)||o.status!=='completed')fail(403,'Оценить можно свой завершённый заказ');const data=z.object({rating:z.number().int().min(1).max(5),review:z.string().trim().max(1000).default('')}).parse(req.body);await q('UPDATE orders SET rating=$1,review=$2 WHERE id=$3',[data.rating,data.review,o.id]);res.json({ok:true});});
 app.get('/api/orders/:id/messages',async(req,res)=>{await orderAccess(req);const after=z.coerce.number().int().min(0).safe().parse(req.query.after||0);res.json(await q('SELECT m.id,m.body,m.sender_id,m.created_at,u.name FROM messages m JOIN users u ON u.id=m.sender_id WHERE order_id=$1 AND m.id>$2 ORDER BY m.id LIMIT 200',[req.params.id,after]));});
 app.post('/api/orders/:id/messages',rateLimit({windowMs:60000,limit:30}),async(req,res)=>{const o=await orderAccess(req);if(['completed','cancelled'].includes(o.status))fail(409,'Чат завершённого заказа доступен для чтения');const {body}=z.object({body:text(2000)}).parse(req.body);const [m]=await q('INSERT INTO messages(order_id,sender_id,body) VALUES($1,$2,$3) RETURNING *',[o.id,req.user.id,body]);res.status(201).json(m);});
 app.get('/api/orders/:id/tip-card',async(req,res)=>{const o=await orderAccess(req);if(!['ready','completed'].includes(o.status))fail(409,'Чаевые доступны после мойки');const [w]=await q('SELECT full_name,card_encrypted FROM washers WHERE user_id=$1',[o.washer_id]);if(!w?.card_encrypted)fail(404,'Мойщик не добавил реквизиты');res.json({name:w.full_name,number:decryptCard(w.card_encrypted,env.CARD_ENCRYPTION_KEY)});});
 app.use('/api/admin',admin);
 app.get('/api/admin/overview',async(req,res)=>{const [stats]=await q(`SELECT count(*)::int AS total, count(*) FILTER(WHERE status NOT IN ('completed','cancelled'))::int AS active, COALESCE(sum(price) FILTER(WHERE payment_status='paid'),0)::text AS revenue,round(avg(rating),1)::text AS rating FROM orders`);res.json(stats);});
 app.get('/api/admin/services',async(req,res)=>res.json(await q('SELECT * FROM services ORDER BY sort_order,id')));
 app.post('/api/admin/services',async(req,res)=>{const d=serviceSchema.parse(req.body);const [s]=await q('INSERT INTO services(name,description,category,price,duration,active) VALUES($1,$2,$3,$4,$5,$6) RETURNING *',Object.values(d));await audit(req.user.id,'service.create',s.id);res.status(201).json(s);});
 app.put('/api/admin/services/:id',async(req,res)=>{const d=serviceSchema.parse(req.body);const [s]=await q('UPDATE services SET name=$1,description=$2,category=$3,price=$4,duration=$5,active=$6 WHERE id=$7 RETURNING *',[...Object.values(d),id.parse(req.params.id)]);if(!s)fail(404,'Услуга не найдена');await audit(req.user.id,'service.update',s.id,{price:d.price,active:d.active});res.json(s);});
 app.get('/api/admin/washers',async(req,res)=>res.json(await q('SELECT w.user_id,w.full_name,w.phone,w.application_status,w.available,u.telegram_id FROM washers w JOIN users u ON u.id=w.user_id ORDER BY w.created_at DESC')));
 app.patch('/api/admin/washers/:id',async(req,res)=>{const {status}=z.object({status:z.enum(['approved','rejected'])}).parse(req.body);const userId=id.parse(req.params.id);const client=await db.connect();try{await client.query('BEGIN');const {rows:[w]}=await client.query('SELECT * FROM washers WHERE user_id=$1 FOR UPDATE',[userId]);if(!w)fail(404,'Заявка не найдена');const {rows:active}=await client.query("SELECT id FROM orders WHERE washer_id=$1 AND status IN ('accepted','washing','ready')",[userId]);if(status==='rejected'&&active.length)fail(409,'Сначала завершите активные заказы мойщика');await client.query('UPDATE washers SET application_status=$1,available=false WHERE user_id=$2',[status,userId]);await client.query("UPDATE users SET role=$1 WHERE id=$2 AND role<>'admin'",[status==='approved'?'washer':'client',userId]);await client.query('INSERT INTO audit(actor_id,action,entity_id,details) VALUES($1,$2,$3,$4)',[req.user.id,'washer.approval',String(userId),JSON.stringify({status})]);await client.query('COMMIT');res.json({ok:true});}catch(e){await client.query('ROLLBACK');throw e;}finally{client.release();}});
 app.get('/api/admin/users',async(req,res)=>res.json(await q('SELECT id,telegram_id,name,phone,role,blocked,created_at FROM users ORDER BY id DESC LIMIT 500')));
 app.patch('/api/admin/users/:id',async(req,res)=>{const userId=id.parse(req.params.id);const {blocked}=z.object({blocked:z.boolean()}).parse(req.body);const [user]=await q('SELECT * FROM users WHERE id=$1',[userId]);if(!user)fail(404,'Пользователь не найден');if(user.role==='admin')fail(403,'Нельзя заблокировать администратора');await q('UPDATE users SET blocked=$1 WHERE id=$2',[blocked,userId]);if(blocked)await q('DELETE FROM sessions WHERE user_id=$1',[userId]);await audit(req.user.id,'user.block',userId,{blocked});res.json({ok:true});});
 app.patch('/api/admin/orders/:id/payment',async(req,res)=>{const {paid}=z.object({paid:z.boolean()}).parse(req.body);const [o]=await q('UPDATE orders SET payment_status=$1 WHERE id=$2 RETURNING id',[paid?'paid':'unpaid',id.parse(req.params.id)]);if(!o)fail(404,'Заказ не найден');await audit(req.user.id,'order.payment',o.id,{paid});res.json({ok:true});});
 app.put('/api/admin/settings',async(req,res)=>{const d=z.object({name:text(80),address:z.string().trim().max(300),contact:z.string().trim().max(100)}).parse(req.body);await q('UPDATE settings SET name=$1,address=$2,contact=$3 WHERE id=1',[d.name,d.address,d.contact]);await audit(req.user.id,'settings.update',1);res.json({ok:true});});
 app.get('/api/admin/audit',async(req,res)=>res.json(await q('SELECT a.*,u.name AS actor_name FROM audit a JOIN users u ON u.id=a.actor_id ORDER BY a.id DESC LIMIT 100')));
 app.use('/api',(req,res)=>res.status(404).json({error:'Метод не найден'}));
 app.use(express.static(resolve('dist'),{index:false}));app.get('/{*path}',(req,res)=>res.sendFile(resolve('dist/index.html')));
 app.use((e,req,res,next)=>{
  if(e instanceof z.ZodError)return res.status(400).json({error:e.issues[0]?.message||'Проверьте заполненные поля'});
  if(e.code==='23505')return res.status(409).json({error:'Запись уже существует или уже есть активный заказ'});
  if(e.type==='entity.too.large')return res.status(413).json({error:'Слишком большой файл или запрос'});
  if(e.type==='entity.parse.failed')return res.status(400).json({error:'Некорректный JSON'});
  if(!e.status) console.error('Request failed',{code:e.code||'INTERNAL',path:req.path});
  res.status(e.status||500).json({error:e.status?e.message:'Ошибка сервера. Попробуйте ещё раз'});
 });return app;
}

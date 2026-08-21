import express from 'express';
import pg from 'pg';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const { Pool } = pg;
const app = express();
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const jwtSecret = process.env.JWT_SECRET;
if (!jwtSecret || !process.env.ADMIN_PASSWORD || !process.env.ADMIN_EMAIL) throw new Error('Missing required environment variables');

app.use(express.json({ limit: '2mb' }));
const auth = (roles = []) => (req, res, next) => {
  try {
    const user = jwt.verify((req.headers.authorization || '').replace('Bearer ', ''), jwtSecret);
    if (roles.length && !roles.includes(user.role)) return res.sendStatus(403);
    req.user = user; next();
  } catch { res.sendStatus(401); }
};

async function init() {
  await pool.query(`CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), first_name TEXT NOT NULL, last_name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL, phone TEXT NOT NULL, password_hash TEXT, role TEXT NOT NULL DEFAULT 'driver', approved BOOLEAN NOT NULL DEFAULT false, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
  ); CREATE TABLE IF NOT EXISTS trips (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), driver_id UUID NOT NULL REFERENCES users(id), status TEXT NOT NULL DEFAULT 'open',
    truck_name TEXT NOT NULL, truck_number TEXT NOT NULL, trailer_name TEXT, trailer_number TEXT, trailer_type TEXT NOT NULL, opened_at TIMESTAMPTZ NOT NULL DEFAULT now(), closed_at TIMESTAMPTZ,
    opening_odometer NUMERIC NOT NULL, opening_truck_fuel NUMERIC NOT NULL DEFAULT 0, opening_reef_fuel NUMERIC, closing_odometer NUMERIC, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
  ); CREATE UNIQUE INDEX IF NOT EXISTS one_open_trip_per_driver ON trips(driver_id) WHERE status = 'open';
  ALTER TABLE trips ADD COLUMN IF NOT EXISTS trailer_number TEXT;
  ALTER TABLE trips ADD COLUMN IF NOT EXISTS opening_truck_fuel NUMERIC NOT NULL DEFAULT 0;
  ALTER TABLE trips ADD COLUMN IF NOT EXISTS opening_reef_fuel NUMERIC;
  CREATE TABLE IF NOT EXISTS trip_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), trip_id UUID NOT NULL REFERENCES trips(id) ON DELETE CASCADE, type TEXT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(), payload JSONB NOT NULL DEFAULT '{}'::jsonb, receipt_url TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
  );`);
  const { rows } = await pool.query('SELECT id FROM users WHERE email=$1', [process.env.ADMIN_EMAIL.toLowerCase()]);
  if (!rows.length) await pool.query('INSERT INTO users(first_name,last_name,email,phone,password_hash,role,approved) VALUES($1,$2,$3,$4,$5,$6,true)', ['System','Admin',process.env.ADMIN_EMAIL.toLowerCase(),'—',await bcrypt.hash(process.env.ADMIN_PASSWORD, 12),'admin']);
}

app.get('/health', async (_, res) => { try { await pool.query('SELECT 1'); res.json({ ok: true }); } catch { res.status(503).json({ ok: false }); } });
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const { rows } = await pool.query('SELECT id,email,role,approved,password_hash,first_name,last_name FROM users WHERE email=$1', [String(email).toLowerCase()]);
  const user = rows[0]; if (!user || !user.approved || !user.password_hash || !(await bcrypt.compare(password || '', user.password_hash))) return res.status(401).json({ error: 'Невірні дані або доступ ще не підтверджено' });
  res.json({ token: jwt.sign({ id:user.id, role:user.role }, jwtSecret, { expiresIn:'12h' }), user: { id:user.id, email:user.email, role:user.role, name:`${user.first_name} ${user.last_name}` } });
});
app.post('/api/auth/register', async (req, res) => {
  const { firstName, lastName, email, phone } = req.body;
  if (![firstName,lastName,email,phone].every(Boolean)) return res.status(400).json({ error:'Заповніть усі поля' });
  try { await pool.query('INSERT INTO users(first_name,last_name,email,phone) VALUES($1,$2,$3,$4)', [firstName,lastName,String(email).toLowerCase(),phone]); res.status(201).json({ ok:true }); }
  catch (e) { res.status(e.code === '23505' ? 409 : 500).json({ error:'Не вдалося створити заявку' }); }
});
app.get('/api/admin/drivers', auth(['admin']), async (_,res) => { const { rows } = await pool.query('SELECT id,first_name,last_name,email,phone,approved,created_at FROM users WHERE role=$1 ORDER BY created_at DESC',['driver']); res.json(rows); });
app.patch('/api/admin/drivers/:id', auth(['admin']), async (req,res) => { const { approved, password }=req.body; const hash=password ? await bcrypt.hash(password,12):null; await pool.query('UPDATE users SET approved=COALESCE($1,approved), password_hash=COALESCE($2,password_hash) WHERE id=$3',[approved,hash,req.params.id]); res.sendStatus(204); });
app.get('/api/trips/current', auth(['driver']), async (req,res) => { const { rows }=await pool.query('SELECT * FROM trips WHERE driver_id=$1 AND status=$2 ORDER BY opened_at DESC LIMIT 1',[req.user.id,'open']); res.json(rows[0]||null); });
app.post('/api/trips', auth(['driver']), async (req,res) => { const t=req.body; if (!t.truckName||!t.truckNumber||!t.trailerType||t.openingOdometer==null||t.openingTruckFuel==null) return res.status(400).json({error:'Заповніть обов’язкові поля'}); if (t.trailerType==='Рефрижератор'&&t.openingReefFuel==null) return res.status(400).json({error:'Для рефрижератора вкажіть ДП у рефі'}); try { const {rows}=await pool.query('INSERT INTO trips(driver_id,truck_name,truck_number,trailer_name,trailer_number,trailer_type,opening_odometer,opening_truck_fuel,opening_reef_fuel) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *',[req.user.id,t.truckName,t.truckNumber,t.trailerName||null,t.trailerNumber||null,t.trailerType,t.openingOdometer,t.openingTruckFuel,t.trailerType==='Рефрижератор'?t.openingReefFuel:null]); res.status(201).json(rows[0]); } catch(e){console.error(e);res.status(e.code==='23505'?409:500).json({error:e.code==='23505'?'Активний рейс уже існує':'Не вдалося відкрити рейс'});} });
app.post('/api/trips/:id/events', auth(['driver']), async (req,res) => { const { type, occurredAt, payload, receiptUrl }=req.body; const {rows}=await pool.query('SELECT * FROM trips WHERE id=$1 AND driver_id=$2 AND status=$3',[req.params.id,req.user.id,'open']); if(!rows[0]) return res.sendStatus(404); const odo=payload?.odometer; if(odo!=null){const last=await pool.query("SELECT COALESCE(MAX((payload->>'odometer')::numeric),$1) odo FROM trip_events WHERE trip_id=$2",[rows[0].opening_odometer,req.params.id]);if(Number(odo)<Number(last.rows[0].odo))return res.status(422).json({error:'Одометр не може зменшуватись'});} const event=await pool.query('INSERT INTO trip_events(trip_id,type,occurred_at,payload,receipt_url) VALUES($1,$2,COALESCE($3,now()),$4,$5) RETURNING *',[req.params.id,type,occurredAt||null,payload||{},receiptUrl||null]);res.status(201).json(event.rows[0]); });
const __dirname=path.dirname(fileURLToPath(import.meta.url)); app.use(express.static(path.join(__dirname,'outputs'))); app.get('*',(_,res)=>res.sendFile(path.join(__dirname,'outputs','index.html')));
init().then(()=>app.listen(process.env.PORT||3000,()=>console.log('Trucks app is running'))).catch(err=>{console.error(err);process.exit(1)});

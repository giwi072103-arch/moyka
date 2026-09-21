CREATE TABLE IF NOT EXISTS users (
 id bigserial PRIMARY KEY, telegram_id text UNIQUE NOT NULL, name text NOT NULL,
 phone text NOT NULL DEFAULT '', role text NOT NULL DEFAULT 'client' CHECK(role IN ('client','washer','admin')),
 blocked boolean NOT NULL DEFAULT false, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS sessions (
 token_hash text PRIMARY KEY, user_id bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 expires_at timestamptz NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (id integer PRIMARY KEY CHECK(id=1), name text NOT NULL, address text NOT NULL DEFAULT '', contact text NOT NULL DEFAULT '');
INSERT INTO settings VALUES(1,'BUKHARA WASH','','') ON CONFLICT DO NOTHING;
CREATE TABLE IF NOT EXISTS services (
 id bigserial PRIMARY KEY, name text NOT NULL, description text NOT NULL, category text NOT NULL,
 price integer NOT NULL CHECK(price>=0), duration integer NOT NULL CHECK(duration BETWEEN 10 AND 480),
 active boolean NOT NULL DEFAULT true, sort_order integer NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS cars (
 id bigserial PRIMARY KEY, user_id bigint NOT NULL REFERENCES users(id), brand text NOT NULL, plate text NOT NULL,
 photo bytea, photo_type text, created_at timestamptz NOT NULL DEFAULT now(), UNIQUE(user_id,plate)
);
CREATE TABLE IF NOT EXISTS washers (
 user_id bigint PRIMARY KEY REFERENCES users(id), full_name text NOT NULL, phone text NOT NULL,
 application_status text NOT NULL DEFAULT 'pending' CHECK(application_status IN ('pending','approved','rejected')),
 available boolean NOT NULL DEFAULT false, card_encrypted text, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS orders (
 id bigserial PRIMARY KEY, user_id bigint NOT NULL REFERENCES users(id), car_id bigint NOT NULL REFERENCES cars(id),
 washer_id bigint REFERENCES users(id), service_id bigint NOT NULL REFERENCES services(id),
 service_name text NOT NULL, price integer NOT NULL CHECK(price>=0), duration integer NOT NULL,
 status text NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','accepted','washing','ready','completed','cancelled')),
 payment_status text NOT NULL DEFAULT 'unpaid' CHECK(payment_status IN ('unpaid','paid')),
 note text NOT NULL DEFAULT '', rating integer CHECK(rating BETWEEN 1 AND 5), review text,
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS one_active_car_order ON orders(car_id) WHERE status IN ('queued','accepted','washing','ready');
CREATE UNIQUE INDEX IF NOT EXISTS one_working_order ON orders(washer_id) WHERE status IN ('accepted','washing');
CREATE INDEX IF NOT EXISTS orders_user_created ON orders(user_id,created_at DESC);
CREATE TABLE IF NOT EXISTS messages (
 id bigserial PRIMARY KEY, order_id bigint NOT NULL REFERENCES orders(id), sender_id bigint NOT NULL REFERENCES users(id),
 body text NOT NULL CHECK(length(body) BETWEEN 1 AND 2000), created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS messages_order_id ON messages(order_id,id);
CREATE TABLE IF NOT EXISTS audit (
 id bigserial PRIMARY KEY, actor_id bigint NOT NULL REFERENCES users(id), action text NOT NULL,
 entity_id text NOT NULL, details jsonb NOT NULL DEFAULT '{}', created_at timestamptz NOT NULL DEFAULT now()
);

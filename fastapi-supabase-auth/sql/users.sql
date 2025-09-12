-- Extensiones seguras
create extension if not exists "pgcrypto";


-- Tabla de usuarios (custom, independiente de Supabase Auth)
create table if not exists public.users (
    id uuid primary key default gen_random_uuid(),
    email text not null unique,
    password_hash text not null,
    created_at timestamptz not null default now()
);


-- Índices útiles
create index if not exists idx_users_email on public.users (email);
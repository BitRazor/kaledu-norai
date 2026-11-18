-- Wishlist mini-app: database for Supabase (run once in the SQL editor).
-- Tables are closed to the public; the web page reaches them only through the
-- wl_* functions below, which check the secret key from the link.

create extension if not exists pgcrypto;

create table if not exists wl_lists (
  id        text primary key,
  title     text not null,
  kid_key   text not null,
  adult_key text not null
);

create table if not exists wl_items (
  id             uuid primary key default gen_random_uuid(),
  list_id        text not null references wl_lists(id) on delete cascade,
  num            int,
  title          text not null,
  kid_text       text,
  adult_text     text,
  image          text,
  price_nok      int,
  price_note     text,
  link           text,
  search         text,
  secret         boolean not null default false,
  added_by       text not null default 'family',
  hearts         int not null default 0 check (hearts between 0 and 3),
  kid_note       text,
  removed_by_kid boolean not null default false,
  ask_note       boolean not null default false,
  sort           int not null default 0,
  created_at     timestamptz not null default now()
);

-- One row per item: the primary key is what makes a double purchase impossible.
create table if not exists wl_claims (
  item_id     uuid primary key references wl_items(id) on delete cascade,
  list_id     text not null references wl_lists(id) on delete cascade,
  buyer       text not null,
  buyer_device text,
  partners    jsonb not null default '[]'::jsonb,
  created_at  timestamptz not null default now()
);

alter table wl_lists  enable row level security;
alter table wl_items  enable row level security;
alter table wl_claims enable row level security;
revoke all on wl_lists, wl_items, wl_claims from anon, authenticated;

create or replace function wl_role(p_list text, p_key text) returns text
language sql stable security definer set search_path = public as $$
  select case when adult_key = p_key then 'adult' when kid_key = p_key then 'kid' end
  from wl_lists where id = p_list
$$;
revoke execute on function wl_role(text, text) from public, anon, authenticated;

create or replace function wl_get(p_list text, p_key text) returns json
language plpgsql stable security definer set search_path = public as $$
declare r text := wl_role(p_list, p_key);
begin
  if r is null then return json_build_object('error', 'bad_key'); end if;
  return json_build_object(
    'role', r,
    'title', (select title from wl_lists where id = p_list),
    'items', coalesce((
      select json_agg(row_to_json(i) order by i.sort, i.created_at) from (
        select id, num, title, kid_text,
               case when r = 'adult' then adult_text end as adult_text,
               image,
               case when r = 'adult' then price_nok end as price_nok,
               case when r = 'adult' then price_note end as price_note,
               link,
               case when r = 'adult' then search end as search,
               secret, added_by, hearts, kid_note, removed_by_kid, ask_note, sort, created_at
        from wl_items
        where list_id = p_list and (r = 'adult' or not secret)
      ) i), '[]'::json),
    'claims', case when r = 'adult' then coalesce((
      select json_agg(row_to_json(c)) from (
        select item_id, buyer, buyer_device, partners, created_at
        from wl_claims where list_id = p_list
      ) c), '[]'::json) else '[]'::json end
  );
end $$;

-- Hearts, the kid's note and "removed" (kid or adult link).
create or replace function wl_kid_set(p_list text, p_key text, p_item uuid,
  p_hearts int default null, p_note text default null, p_removed boolean default null) returns json
language plpgsql volatile security definer set search_path = public as $$
declare r text := wl_role(p_list, p_key);
begin
  if r is null then return json_build_object('ok', false, 'error', 'bad_key'); end if;
  update wl_items set
    hearts = coalesce(greatest(0, least(3, p_hearts)), hearts),
    kid_note = coalesce(left(p_note, 120), kid_note),
    removed_by_kid = coalesce(p_removed, removed_by_kid)
  where id = p_item and list_id = p_list and (r = 'adult' or not secret);
  return json_build_object('ok', found);
end $$;

create or replace function wl_add_item(p_list text, p_key text, p_item jsonb) returns json
language plpgsql volatile security definer set search_path = public as $$
declare r text := wl_role(p_list, p_key); new_id uuid; s int; n int;
begin
  if r is null then return json_build_object('ok', false, 'error', 'bad_key'); end if;
  if coalesce(trim(p_item->>'title'), '') = '' then return json_build_object('ok', false, 'error', 'title'); end if;
  select coalesce(max(sort), 0) + 1 into s from wl_items where list_id = p_list;
  if r = 'kid' then
    select coalesce(max(num), 0) + 1 into n from wl_items where list_id = p_list;
    insert into wl_items (list_id, num, title, kid_text, link, added_by, secret, sort, hearts)
    values (p_list, n, left(trim(p_item->>'title'), 80), left(p_item->>'kid_text', 200),
            left(p_item->>'link', 500), 'kid', false, s,
            greatest(0, least(3, coalesce(case when (p_item->>'hearts') ~ '^[0-9]$' then (p_item->>'hearts')::int end, 3))))
    returning id into new_id;
  else
    insert into wl_items (list_id, title, kid_text, adult_text, image, price_nok, price_note, link, search, secret, added_by, sort)
    values (p_list, left(trim(p_item->>'title'), 80), left(p_item->>'kid_text', 200), left(p_item->>'adult_text', 400),
            left(p_item->>'image', 500),
            case when (p_item->>'price_nok') ~ '^[0-9]{1,7}$' then (p_item->>'price_nok')::int end,
            left(p_item->>'price_note', 80), left(p_item->>'link', 500), left(p_item->>'search', 120),
            coalesce((p_item->>'secret')::boolean, false), 'family', s)
    returning id into new_id;
  end if;
  return json_build_object('ok', true, 'id', new_id);
end $$;

create or replace function wl_update_item(p_list text, p_key text, p_item_id uuid, p_item jsonb) returns json
language plpgsql volatile security definer set search_path = public as $$
begin
  if wl_role(p_list, p_key) is distinct from 'adult' then return json_build_object('ok', false, 'error', 'not_adult'); end if;
  update wl_items set
    title      = case when p_item ? 'title' and trim(p_item->>'title') <> '' then left(trim(p_item->>'title'), 80) else title end,
    kid_text   = case when p_item ? 'kid_text'   then left(p_item->>'kid_text', 200)   else kid_text end,
    adult_text = case when p_item ? 'adult_text' then left(p_item->>'adult_text', 400) else adult_text end,
    image      = case when p_item ? 'image'      then left(p_item->>'image', 500)      else image end,
    price_nok  = case when p_item ? 'price_nok'  then (case when (p_item->>'price_nok') ~ '^[0-9]{1,7}$' then (p_item->>'price_nok')::int end) else price_nok end,
    price_note = case when p_item ? 'price_note' then left(p_item->>'price_note', 80)  else price_note end,
    link       = case when p_item ? 'link'       then left(p_item->>'link', 500)       else link end,
    secret     = case when p_item ? 'secret'     then coalesce((p_item->>'secret')::boolean, false) else secret end,
    ask_note   = case when p_item ? 'ask_note'   then coalesce((p_item->>'ask_note')::boolean, false) else ask_note end
  where id = p_item_id and list_id = p_list;
  return json_build_object('ok', found);
end $$;

create or replace function wl_delete_item(p_list text, p_key text, p_item uuid) returns json
language plpgsql volatile security definer set search_path = public as $$
begin
  if wl_role(p_list, p_key) is distinct from 'adult' then return json_build_object('ok', false, 'error', 'not_adult'); end if;
  delete from wl_items where id = p_item and list_id = p_list;
  return json_build_object('ok', found);
end $$;

create or replace function wl_claim(p_list text, p_key text, p_item uuid, p_buyer text, p_device text) returns json
language plpgsql volatile security definer set search_path = public as $$
begin
  if wl_role(p_list, p_key) is distinct from 'adult' then return json_build_object('ok', false, 'error', 'not_adult'); end if;
  if coalesce(trim(p_buyer), '') = '' then return json_build_object('ok', false, 'error', 'name'); end if;
  if not exists (select 1 from wl_items where id = p_item and list_id = p_list) then
    return json_build_object('ok', false, 'error', 'not_found');
  end if;
  insert into wl_claims (item_id, list_id, buyer, buyer_device)
  values (p_item, p_list, left(trim(p_buyer), 40), left(p_device, 64))
  on conflict (item_id) do nothing;
  if found then return json_build_object('ok', true); end if;
  return json_build_object('ok', false, 'error', 'taken',
    'buyer', (select buyer from wl_claims where item_id = p_item));
end $$;

create or replace function wl_unclaim(p_list text, p_key text, p_item uuid, p_device text, p_force boolean default false) returns json
language plpgsql volatile security definer set search_path = public as $$
declare b text; d text;
begin
  if wl_role(p_list, p_key) is distinct from 'adult' then return json_build_object('ok', false, 'error', 'not_adult'); end if;
  select buyer, buyer_device into b, d from wl_claims where item_id = p_item and list_id = p_list;
  if not found then return json_build_object('ok', true); end if;
  if d is distinct from p_device and not coalesce(p_force, false) then
    return json_build_object('ok', false, 'error', 'not_yours', 'buyer', b);
  end if;
  delete from wl_claims where item_id = p_item and list_id = p_list;
  return json_build_object('ok', true);
end $$;

-- Join or leave a shared purchase ("susidedame").
create or replace function wl_join(p_list text, p_key text, p_item uuid, p_name text, p_leave boolean default false) returns json
language plpgsql volatile security definer set search_path = public as $$
declare nm text := left(trim(coalesce(p_name, '')), 40);
begin
  if wl_role(p_list, p_key) is distinct from 'adult' then return json_build_object('ok', false, 'error', 'not_adult'); end if;
  if nm = '' then return json_build_object('ok', false, 'error', 'name'); end if;
  update wl_claims set partners = case
      when coalesce(p_leave, false) then
        (select coalesce(jsonb_agg(x), '[]'::jsonb) from jsonb_array_elements_text(partners) x where x <> nm)
      when partners ? nm or buyer = nm then partners
      else partners || to_jsonb(nm) end
  where item_id = p_item and list_id = p_list;
  return json_build_object('ok', found);
end $$;

grant execute on function wl_get(text, text), wl_kid_set(text, text, uuid, int, text, boolean),
  wl_add_item(text, text, jsonb), wl_update_item(text, text, uuid, jsonb), wl_delete_item(text, text, uuid),
  wl_claim(text, text, uuid, text, text), wl_unclaim(text, text, uuid, text, boolean),
  wl_join(text, text, uuid, text, boolean) to anon, authenticated;

import psycopg2

PASSW = input('Пароль:  ')

conn = psycopg2.connect(
    dbname='authdb',
    user='postgres',
    password=PASSW,
    host='localhost',
    port=5432
)

with conn.cursor() as cur:
    cur.execute("""
        DO $$
        DECLARE r RECORD;
        BEGIN
            FOR r IN (
                SELECT tablename
                FROM pg_tables
                WHERE schemaname = 'public'
            ) LOOP
                EXECUTE 'DROP TABLE IF EXISTS public.' || quote_ident(r.tablename) || ' CASCADE';
            END LOOP;
        END $$;
    """)
    conn.commit()

conn.close()
print('Все таблицы в public удалены')
import psycopg2
import psycopg2.extras
import bcrypt


def open_create_BD(passw: str):
    return psycopg2.connect(
        user='postgres',
        password=passw,
        host='localhost',
        port='5432',
        database='authdb'
    )


def create_table(connection, name_table: str, params: str):
    with connection.cursor() as cur:
        cur.execute(f'CREATE TABLE IF NOT EXISTS {name_table} ({params});')
        connection.commit()


def query_db(sql, params=(), fetch=False, one=False):
    conn = psycopg2.connect(
        dbname='authdb',
        user='postgres',
        password=PASSW,
        host='localhost',
        port=5432
    )
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(sql, params)

        if one:
            res = cur.fetchone()
        elif fetch:
            res = cur.fetchall()
        else:
            res = None

        conn.commit()
        cur.close()
        return res
    finally:
        conn.close()


def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def check_password(password, hash_):
    return bcrypt.checkpw(password.encode(), hash_.encode())


def init_rbac_tables(connection):
    with connection.cursor() as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS app_meta (
                id SERIAL PRIMARY KEY,
                key_name VARCHAR(100) UNIQUE NOT NULL,
                key_value VARCHAR(100) NOT NULL
            );
        """)

        cur.execute("""
            SELECT EXISTS (
                SELECT 1
                FROM app_meta
                WHERE key_name = 'initialized' AND key_value = 'true'
            );
        """)
        already_done = cur.fetchone()[0]

        if already_done:
            print("База уже инициализирована")
            return

        cur.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto;")

        create_table(connection, 'users', """
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            first_name VARCHAR(50) NOT NULL,
            last_name VARCHAR(50) NOT NULL,
            patronymic VARCHAR(50),
            email VARCHAR(100) UNIQUE NOT NULL,
            password_hash VARCHAR(128) NOT NULL,
            is_active BOOLEAN DEFAULT TRUE,
            last_login TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_primary_admin BOOLEAN NOT NULL DEFAULT FALSE
        """)

        create_table(connection, 'roles', """
            id SERIAL PRIMARY KEY,
            name VARCHAR(50) UNIQUE NOT NULL
        """)

        create_table(connection, 'permissions', """
            id SERIAL PRIMARY KEY,
            name VARCHAR(100) UNIQUE NOT NULL
        """)

        create_table(connection, 'resources', """
            id SERIAL PRIMARY KEY,
            name VARCHAR(50) UNIQUE NOT NULL
        """)

        create_table(connection, 'user_roles', """
            user_id UUID REFERENCES users(id) ON DELETE CASCADE,
            role_id INTEGER REFERENCES roles(id) ON DELETE CASCADE,
            PRIMARY KEY (user_id, role_id)
        """)

        create_table(connection, 'role_permissions', """
            role_id INTEGER REFERENCES roles(id) ON DELETE CASCADE,
            permission_id INTEGER REFERENCES permissions(id) ON DELETE CASCADE,
            PRIMARY KEY (role_id, permission_id)
        """)

        create_table(connection, 'permission_resources', """
            permission_id INTEGER REFERENCES permissions(id) ON DELETE CASCADE,
            resource_id INTEGER REFERENCES resources(id) ON DELETE CASCADE,
            can_read BOOLEAN DEFAULT FALSE,
            can_write BOOLEAN DEFAULT FALSE,
            can_delete BOOLEAN DEFAULT FALSE,
            PRIMARY KEY (permission_id, resource_id)
        """)

        create_table(connection, 'posts', """
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            title VARCHAR(200) NOT NULL,
            text TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        """)

        create_table(connection, 'sessions', """
            token UUID PRIMARY KEY,
            user_id UUID REFERENCES users(id) ON DELETE CASCADE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL
        """)

        cur.execute("""
            INSERT INTO roles (name)
            VALUES ('admin'), ('moderator'), ('user')
            ON CONFLICT DO NOTHING;
        """)

        cur.execute("""
            INSERT INTO permissions (name)
            VALUES
                ('posts_read_all'),
                ('posts_create_own'),
                ('posts_update_own'),
                ('posts_update_all'),
                ('posts_delete_own'),
                ('posts_delete_all'),
                ('users_read'),
                ('users_write'),
                ('users_delete'),
                ('roles_manage')
            ON CONFLICT DO NOTHING;
        """)

        cur.execute("""
            INSERT INTO resources (name)
            VALUES ('posts'), ('users'), ('roles')
            ON CONFLICT DO NOTHING;
        """)

        cur.execute("SELECT id, name FROM roles;")
        roles = {name: rid for rid, name in cur.fetchall()}

        cur.execute("SELECT id, name FROM permissions;")
        perms = {name: pid for pid, name in cur.fetchall()}

        cur.execute("SELECT id, name FROM resources;")
        resources = {name: rid for rid, name in cur.fetchall()}

        role_perm_pairs = [
            (roles['user'], perms['posts_read_all']),
            (roles['user'], perms['posts_create_own']),
            (roles['user'], perms['posts_update_own']),
            (roles['user'], perms['posts_delete_own']),

            (roles['moderator'], perms['posts_read_all']),
            (roles['moderator'], perms['posts_create_own']),
            (roles['moderator'], perms['posts_update_own']),
            (roles['moderator'], perms['posts_update_all']),
            (roles['moderator'], perms['posts_delete_own']),
            (roles['moderator'], perms['posts_delete_all']),
            (roles['moderator'], perms['users_read']),

            (roles['admin'], perms['posts_read_all']),
            (roles['admin'], perms['posts_create_own']),
            (roles['admin'], perms['posts_update_own']),
            (roles['admin'], perms['posts_update_all']),
            (roles['admin'], perms['posts_delete_own']),
            (roles['admin'], perms['posts_delete_all']),
            (roles['admin'], perms['users_read']),
            (roles['admin'], perms['users_write']),
            (roles['admin'], perms['users_delete']),
            (roles['admin'], perms['roles_manage']),
        ]

        cur.executemany(
            "INSERT INTO role_permissions (role_id, permission_id) VALUES (%s, %s) ON CONFLICT DO NOTHING;",
            role_perm_pairs
        )

        pr_rows = [
            (perms['posts_read_all'], resources['posts'], True, False, False),
            (perms['posts_create_own'], resources['posts'], False, True, False),
            (perms['posts_update_own'], resources['posts'], False, True, False),
            (perms['posts_update_all'], resources['posts'], False, True, False),
            (perms['posts_delete_own'], resources['posts'], False, False, True),
            (perms['posts_delete_all'], resources['posts'], False, False, True),

            (perms['users_read'], resources['users'], True, False, False),
            (perms['users_write'], resources['users'], False, True, False),
            (perms['users_delete'], resources['users'], False, False, True),

            (perms['roles_manage'], resources['roles'], True, True, True),
        ]

        cur.executemany(
            """
            INSERT INTO permission_resources
                (permission_id, resource_id, can_read, can_write, can_delete)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT DO NOTHING;
            """,
            pr_rows
        )

        cur.execute("""
            INSERT INTO app_meta (key_name, key_value)
            VALUES ('initialized', 'true')
            ON CONFLICT (key_name) DO UPDATE SET key_value = EXCLUDED.key_value;
        """)

        connection.commit()
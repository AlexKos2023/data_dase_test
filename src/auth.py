"""При первом запуске приложения:

python
init_first_primary_admin(
    'Главный',
    'Админ',
    'Системный',
    'admin@mail.com',
    '123456'
)"""

from db import query_db, hash_password, check_password
from psycopg2.errors import UniqueViolation
from datetime import datetime, timedelta
import uuid
from db import query_db, hash_password, check_password
from permissions import has_role, is_superadmin


def register_user(first_name, last_name, patronymic, email, password, password_repeat):
    if not first_name or not last_name or not email or not password:
        return False, 'Не все поля заполнены'
    if password != password_repeat:
        return False, 'Пароли не совпадают'

    exists = query_db('SELECT id FROM users WHERE email = %s', (email,), one=True)
    if exists:
        return False, 'Пользователь с таким email уже существует'

    password_hash = hash_password(password)
    query_db(
        """
        INSERT INTO users (
            first_name, last_name, patronymic, email, password_hash, is_active, is_primary_admin
        ) VALUES (%s, %s, %s, %s, %s, TRUE, FALSE)
        """,
        (first_name, last_name, patronymic, email, password_hash)
    )
    return True, 'Пользователь зарегистрирован'


def init_first_primary_admin(first_name, last_name, patronymic, email, password):
    exists = query_db(
        'SELECT id FROM users WHERE is_primary_admin = TRUE AND is_active = TRUE',
        one=True
    )
    if exists:
        return False, 'Главный администратор уже существует'

    if not first_name or not last_name or not email or not password:
        return False, 'Не все поля заполнены'

    user_exists = query_db('SELECT id FROM users WHERE email = %s', (email,), one=True)
    if user_exists:
        return False, 'Пользователь с таким email уже существует'

    password_hash = hash_password(password)
    query_db(
        """
        INSERT INTO users (
            first_name, last_name, patronymic, email, password_hash, is_active, is_primary_admin
        ) VALUES (%s, %s, %s, %s, %s, TRUE, TRUE)
        """,
        (first_name, last_name, patronymic, email, password_hash)
    )

    user = query_db('SELECT id FROM users WHERE email = %s', (email,), one=True)
    admin_role = query_db('SELECT id FROM roles WHERE name = %s', ('admin',), one=True)

    if user and admin_role:
        query_db(
            'INSERT INTO user_roles (user_id, role_id) VALUES (%s, %s) ON CONFLICT DO NOTHING',
            (user['id'], admin_role['id'])
        )

    return True, 'Главный администратор создан'


def login_user(email, password):
    user = query_db(
        """
        SELECT id, email, password_hash, is_active, is_primary_admin
        FROM users
        WHERE email = %s
        """,
        (email,),
        one=True
    )

    if not user:
        return False, 'Неверный email или пароль', None

    if not user['is_active']:
        return False, 'Пользователь деактивирован', None

    if not check_password(password, user['password_hash']):
        return False, 'Неверный email или пароль', None

    token = str(uuid.uuid4())
    expires_at = datetime.now() + timedelta(days=7)

    query_db(
        """
        INSERT INTO sessions (token, user_id, expires_at)
        VALUES (%s, %s, %s)
        """,
        (token, user['id'], expires_at)
    )

    query_db(
        """
        UPDATE users
        SET last_login = CURRENT_TIMESTAMP
        WHERE id = %s
        """,
        (user['id'],)
    )

    return True, 'Успешный вход', token


def get_current_user(token):
    user = query_db(
        """
        SELECT u.id, u.first_name, u.last_name, u.patronymic, u.email,
               u.is_active, u.is_primary_admin
        FROM sessions s
        JOIN users u ON s.user_id = u.id
        WHERE s.token = %s
          AND s.expires_at > CURRENT_TIMESTAMP
          AND u.is_active = TRUE
        """,
        (token,),
        one=True
    )
    return user


def delete_account(token):
    user = get_current_user(token)
    if not user:
        return False, 'Пользователь не авторизован'

    if user['is_primary_admin']:
        return False, 'Главного администратора удалить нельзя'

    user_id = user['id']

    query_db('UPDATE users SET is_active = FALSE WHERE id = %s', (user_id,))
    query_db('DELETE FROM sessions WHERE user_id = %s', (user_id,))
    return True, 'Аккаунт деактивирован'


def delete_user_by_id(token, target_user_id):
    actor = get_current_user(token)
    if not actor:
        return False, 'Пользователь не авторизован'

    target = query_db(
        'SELECT id, is_primary_admin FROM users WHERE id = %s',
        (target_user_id,),
        one=True
    )
    if not target:
        return False, 'Пользователь не найден'

    if target['is_primary_admin']:
        return False, 'Главного администратора удалить нельзя'

    if not (actor['is_primary_admin'] or has_role(actor['id'], 'admin')):
        return False, 'Недостаточно прав'

    query_db('UPDATE users SET is_active = FALSE WHERE id = %s', (target_user_id,))
    query_db('DELETE FROM sessions WHERE user_id = %s', (target_user_id,))
    return True, 'Пользователь деактивирован'


def assign_role_to_user(token, email, role_name):
    caller = get_current_user(token)
    if not caller:
        return False, 'Пользователь не авторизован'

    if not has_permission(caller['id'], 'roles_manage'):
        return False, 'Недостаточно прав'

    user = query_db(
        "SELECT id, is_active FROM users WHERE email = %s;",
        (email,),
        one=True
    )
    if not user:
        return False, 'Пользователь не найден'

    role = query_db(
        "SELECT id FROM roles WHERE name = %s;",
        (role_name,),
        one=True
    )
    if not role:
        return False, 'Роль не найдена'

    query_db(
        "INSERT INTO user_roles (user_id, role_id) VALUES (%s, %s) ON CONFLICT DO NOTHING;",
        (user['id'], role['id'])
    )
    return True, 'Роль назначена'

from db import query_db


def has_permission(user_id, permission_name):
    rows = query_db("""
        SELECT 1
        FROM user_roles ur
        JOIN role_permissions rp ON rp.role_id = ur.role_id
        JOIN permissions p ON p.id = rp.permission_id
        WHERE ur.user_id = %s
          AND p.name = %s
        LIMIT 1;
    """, (user_id, permission_name), fetch=True)

    return bool(rows)

def auth_admin():
    token = get_bearer_token()
    if not token:
        return None, response(401, "Unauthorized")

    user = get_current_user(token)
    if not user:
        return None, response(401, "Unauthorized")

    status_code, message, _ = check_access(token, "roles_manage")
    if status_code != 200:
        return None, response(status_code, message)

    return user, None
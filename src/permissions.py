from db import query_db


def has_role(user_id, role_name):
    row = query_db("""
        SELECT 1
        FROM user_roles ur
        JOIN roles r ON ur.role_id = r.id
        WHERE ur.user_id = %s AND r.name = %s
        LIMIT 1
    """, (user_id, role_name), one=True)
    return row is not None


def is_superadmin(user):
    return bool(user and user.get('is_primary_admin'))


def get_post(post_id):
    return query_db(
        """
        SELECT id, user_id, title, text, created_at, updated_at
        FROM posts
        WHERE id = %s
        """,
        (post_id,),
        one=True
    )


def can_read_posts(user):
    return bool(user) and (
        has_role(user['id'], 'user')
        or has_role(user['id'], 'moderator')
        or has_role(user['id'], 'admin')
        or is_superadmin(user)
    )


def can_create_post(user):
    return bool(user) and (
        has_role(user['id'], 'user')
        or has_role(user['id'], 'moderator')
        or has_role(user['id'], 'admin')
        or is_superadmin(user)
    )


def can_update_post(user, post_owner_id):
    if not user:
        return False
    if is_superadmin(user):
        return True
    if has_role(user['id'], 'moderator') or has_role(user['id'], 'admin'):
        return True
    return user['id'] == post_owner_id


def can_delete_post(user, post_owner_id):
    if not user:
        return False
    if is_superadmin(user):
        return True
    if has_role(user['id'], 'moderator') or has_role(user['id'], 'admin'):
        return True
    return user['id'] == post_owner_id


def check_access(token, action, post_owner_id=None):
    from auth import get_current_user

    user = get_current_user(token)
    if not user:
        return 401, 'Unauthorized', None

    if action == 'posts_read':
        allowed = has_role(user['id'], 'user') or has_role(user['id'], 'moderator') or has_role(user['id'], 'admin') or is_superadmin(user)
    elif action == 'posts_create':
        allowed = has_role(user['id'], 'user') or has_role(user['id'], 'moderator') or has_role(user['id'], 'admin') or is_superadmin(user)
    elif action == 'posts_update':
        allowed = is_superadmin(user) or has_role(user['id'], 'moderator') or has_role(user['id'], 'admin') or user['id'] == post_owner_id
    elif action == 'posts_delete':
        allowed = is_superadmin(user) or has_role(user['id'], 'moderator') or has_role(user['id'], 'admin') or user['id'] == post_owner_id
    elif action == 'roles_manage':
        allowed = is_superadmin(user) or has_role(user['id'], 'admin')
    elif action == 'users_read':
        allowed = is_superadmin(user) or has_role(user['id'], 'moderator') or has_role(user['id'], 'admin')
    else:
        allowed = False

    if not allowed:
        return 403, 'Forbidden', user

    return 200, 'OK', user
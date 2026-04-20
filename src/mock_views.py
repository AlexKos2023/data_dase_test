from db import query_db
from permissions import check_access, get_post


def _response(status_code, message, data=None):
    return {
        'status_code': status_code,
        'message': message,
        'data': data
    }


def get_posts(token):
    status_code, message, user = check_access(token, 'posts_read')
    if status_code != 200:
        return _response(status_code, message)

    posts = query_db(
        """
        SELECT p.id, p.title, p.text, p.created_at, u.email AS author_email
        FROM posts p
        JOIN users u ON p.user_id = u.id
        ORDER BY p.created_at DESC
        """,
        fetch=True
    )
    return _response(200, 'OK', posts)


def create_post(token, title, text):
    status_code, message, user = check_access(token, 'posts_create')
    if status_code != 200:
        return _response(status_code, message)

    post_id = query_db(
        """
        INSERT INTO posts (user_id, title, text)
        VALUES (%s, %s, %s)
        RETURNING id, user_id, title, text, created_at, updated_at
        """,
        (user['id'], title, text),
        one=True
    )
    return _response(200, 'Post created', post_id)


def update_post(token, post_id, title, text):
    post = get_post(post_id)
    if not post:
        return _response(404, 'Post not found')

    status_code, message, user = check_access(token, 'posts_update', post_owner_id=post['user_id'])
    if status_code != 200:
        return _response(status_code, message)

    updated = query_db(
        """
        UPDATE posts
        SET title = %s, text = %s, updated_at = CURRENT_TIMESTAMP
        WHERE id = %s
        RETURNING id, user_id, title, text, created_at, updated_at
        """,
        (title, text, post_id),
        one=True
    )
    return _response(200, 'Post updated', updated)


def delete_post(token, post_id):
    post = get_post(post_id)
    if not post:
        return _response(404, 'Post not found')

    status_code, message, user = check_access(token, 'posts_delete', post_owner_id=post['user_id'])
    if status_code != 200:
        return _response(status_code, message)

    query_db('DELETE FROM posts WHERE id = %s', (post_id,))
    return _response(200, f'Post {post_id} deleted')
from flask import Flask, request, jsonify
from db import query_db
from permissions import check_access, get_post

app = Flask(__name__)

def _response(status_code, message, data=None):
    return jsonify({
        "status_code": status_code,
        "message": message,
        "data": data
    }), status_code

def get_token():
    return request.args.get("token", "").strip() or None

@app.get("/posts")
def posts():
    token = get_token()
    status_code, message, user = check_access(token, "posts_read")
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
    return _response(200, "OK", posts)

@app.post("/posts")
def create_post_view():
    token = get_token()
    title = request.json.get("title")
    text = request.json.get("text")

    status_code, message, user = check_access(token, "posts_create")
    if status_code != 200:
        return _response(status_code, message)

    post_id = query_db(
        """
        INSERT INTO posts (user_id, title, text)
        VALUES (%s, %s, %s)
        RETURNING id, user_id, title, text, created_at, updated_at
        """,
        (user["id"], title, text),
        one=True
    )
    return _response(200, "Post created", post_id)

@app.put("/posts/<int:post_id>")
def update_post_view(post_id):
    token = get_token()
    title = request.json.get("title")
    text = request.json.get("text")

    post = get_post(post_id)
    if not post:
        return _response(404, "Post not found")

    status_code, message, user = check_access(token, "posts_update", post_owner_id=post["user_id"])
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
    return _response(200, "Post updated", updated)

@app.delete("/posts/<int:post_id>")
def delete_post_view(post_id):
    token = get_token()
    post = get_post(post_id)
    if not post:
        return _response(404, "Post not found")

    status_code, message, user = check_access(token, "posts_delete", post_owner_id=post["user_id"])
    if status_code != 200:
        return _response(status_code, message)

    query_db("DELETE FROM posts WHERE id = %s", (post_id,))
    return _response(200, f"Post {post_id} deleted")

if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5002)
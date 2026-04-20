from flask import Flask, request, jsonify

from db import query_db
from auth import get_current_user
from permissions import check_access

app = Flask(__name__)


def response(status_code, message, data=None):
    return jsonify({"message": message, "data": data}), status_code


def get_bearer_token():
    auth = request.headers.get("Authorization", "")
    parts = auth.split()

    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1].strip():
        return None

    return parts[1].strip()


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


def row_to_dict(row):
    return dict(row) if row is not None else None


@app.get("/admin/roles")
def get_roles():
    user, error = auth_admin()
    if error:
        return error

    roles = query_db("SELECT id, name FROM roles ORDER BY id;", fetch=True)
    return response(200, "OK", [row_to_dict(r) for r in roles])


@app.get("/admin/permissions")
def get_permissions():
    user, error = auth_admin()
    if error:
        return error

    permissions = query_db("SELECT id, name FROM permissions ORDER BY id;", fetch=True)
    return response(200, "OK", [row_to_dict(r) for r in permissions])


@app.get("/admin/resources")
def get_resources():
    user, error = auth_admin()
    if error:
        return error

    resources = query_db("SELECT id, name FROM resources ORDER BY id;", fetch=True)
    return response(200, "OK", [row_to_dict(r) for r in resources])


@app.get("/admin/role-permissions")
def get_role_permissions():
    user, error = auth_admin()
    if error:
        return error

    rows = query_db("""
        SELECT
            r.name AS role_name,
            p.name AS permission_name
        FROM role_permissions rp
        JOIN roles r ON r.id = rp.role_id
        JOIN permissions p ON p.id = rp.permission_id
        ORDER BY r.name, p.name;
    """, fetch=True)

    return response(200, "OK", [row_to_dict(r) for r in rows])


@app.post("/admin/assign-role")
def assign_role():
    user, error = auth_admin()
    if error:
        return error

    data = request.get_json(silent=True) or {}
    email = data.get("email")
    role_name = data.get("role_name")

    if not email or not role_name:
        return response(400, "email and role_name are required")

    if role_name == "admin" and not user.get("is_primary_admin", False):
        return response(403, "Forbidden")

    target = query_db("SELECT id FROM users WHERE email = %s;", (email,), one=True)
    if not target:
        return response(404, "User not found")

    role = query_db("SELECT id FROM roles WHERE name = %s;", (role_name,), one=True)
    if not role:
        return response(404, "Role not found")

    query_db(
        """
        INSERT INTO user_roles (user_id, role_id)
        VALUES (%s, %s)
        ON CONFLICT DO NOTHING;
        """,
        (target["id"], role["id"])
    )
    return response(200, "Role assigned")


@app.delete("/admin/remove-role")
def remove_role():
    user, error = auth_admin()
    if error:
        return error

    data = request.get_json(silent=True) or {}
    email = data.get("email")
    role_name = data.get("role_name")

    if not email or not role_name:
        return response(400, "email and role_name are required")

    target = query_db("SELECT id FROM users WHERE email = %s;", (email,), one=True)
    if not target:
        return response(404, "User not found")

    role = query_db("SELECT id FROM roles WHERE name = %s;", (role_name,), one=True)
    if not role:
        return response(404, "Role not found")

    query_db(
        "DELETE FROM user_roles WHERE user_id = %s AND role_id = %s;",
        (target["id"], role["id"])
    )
    return response(200, "Role removed")


@app.post("/admin/role-permission")
def add_role_permission():
    user, error = auth_admin()
    if error:
        return error

    data = request.get_json(silent=True) or {}
    role_name = data.get("role_name")
    permission_name = data.get("permission_name")

    if not role_name or not permission_name:
        return response(400, "role_name and permission_name are required")

    role = query_db("SELECT id FROM roles WHERE name = %s;", (role_name,), one=True)
    if not role:
        return response(404, "Role not found")

    permission = query_db("SELECT id FROM permissions WHERE name = %s;", (permission_name,), one=True)
    if not permission:
        return response(404, "Permission not found")

    resource = query_db("""
        SELECT id
        FROM resources
        WHERE name = CASE
            WHEN %s LIKE 'posts%%' THEN 'posts'
            WHEN %s LIKE 'users%%' THEN 'users'
            WHEN %s LIKE 'roles%%' THEN 'roles'
            ELSE NULL
        END;
    """, (permission_name, permission_name, permission_name), one=True)

    if not resource:
        return response(404, "Resource not found")

    can_read = permission_name.endswith("_read_all") or permission_name.endswith("_read")
    can_write = (
        permission_name.endswith("_create_own")
        or permission_name.endswith("_update_own")
        or permission_name.endswith("_update_all")
        or permission_name.endswith("_write")
    )
    can_delete = (
        permission_name.endswith("_delete_own")
        or permission_name.endswith("_delete_all")
        or permission_name.endswith("_delete")
    )

    query_db(
        """
        INSERT INTO permission_resources
            (permission_id, resource_id, can_read, can_write, can_delete)
        VALUES (%s, %s, %s, %s, %s)
        ON CONFLICT DO NOTHING;
        """,
        (permission["id"], resource["id"], can_read, can_write, can_delete)
    )

    query_db(
        """
        INSERT INTO role_permissions (role_id, permission_id)
        VALUES (%s, %s)
        ON CONFLICT DO NOTHING;
        """,
        (role["id"], permission["id"])
    )

    return response(200, "Permission assigned to role")


@app.delete("/admin/role-permission")
def remove_role_permission():
    user, error = auth_admin()
    if error:
        return error

    data = request.get_json(silent=True) or {}
    role_name = data.get("role_name")
    permission_name = data.get("permission_name")

    if not role_name or not permission_name:
        return response(400, "role_name and permission_name are required")

    role = query_db("SELECT id FROM roles WHERE name = %s;", (role_name,), one=True)
    if not role:
        return response(404, "Role not found")

    permission = query_db("SELECT id FROM permissions WHERE name = %s;", (permission_name,), one=True)
    if not permission:
        return response(404, "Permission not found")

    query_db(
        "DELETE FROM role_permissions WHERE role_id = %s AND permission_id = %s;",
        (role["id"], permission["id"])
    )
    return response(200, "Permission removed from role")


if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
import threading
from collections.abc import Iterable, Mapping


DOCS = {
    "doc-alice": {"owner": "alice", "tenant": "t1", "deleted": False, "title": "alice"},
    "doc-bob": {"owner": "bob", "tenant": "t1", "deleted": False, "title": "bob"},
    "doc-carol": {"owner": "carol", "tenant": "t2", "deleted": True, "title": "carol"},
}

# Authorization data is supplied by the application. Keeping it configurable
# avoids baking any particular login name into the policy.
USERS = {}
ROLES = {}
USER_TENANTS = {}
ADMINS = set()
ADMIN_TENANTS = {}

# Only these document fields may be changed through update_doc. Ownership and
# tenant metadata are deliberately absent, and are also checked separately.
UPDATABLE_FIELDS = frozenset({"title", "content", "description", "tags"})
IMMUTABLE_FIELDS = frozenset(
    {
        "id",
        "doc_id",
        "owner",
        "tenant",
        "role",
        "deleted",
        "is_deleted",
    }
)
ADMIN_ROLES = frozenset({"admin", "administrator", "superadmin"})

_LOCK = threading.RLock()


def _valid_id(value):
    return isinstance(value, str) and bool(value.strip())


def _principal(user):
    """Return (user id, explicit role, explicit tenant) for a principal."""
    if isinstance(user, str):
        return user, None, None

    if isinstance(user, Mapping):
        user_id = (
            user.get("id")
            or user.get("user_id")
            or user.get("username")
            or user.get("name")
            or user.get("user")
        )
        role = user.get("role")
        tenant = user.get("tenant") or user.get("tenant_id")
        return user_id, role, tenant

    user_id = getattr(user, "id", None) or getattr(user, "username", None)
    role = getattr(user, "role", None)
    tenant = getattr(user, "tenant", None) or getattr(user, "tenant_id", None)
    return user_id, role, tenant


def _record_for(user_id):
    store = USERS if isinstance(USERS, Mapping) else {}
    record = store.get(user_id)
    return record if isinstance(record, Mapping) else {}


def _role_for(user_id, explicit_role=None):
    if explicit_role is not None:
        return explicit_role
    record = _record_for(user_id)
    role = record.get("role")
    if role is not None:
        return role
    if isinstance(ROLES, Mapping):
        return ROLES.get(user_id)
    return None


def _tenant_values(value):
    if value is None:
        return set()
    if isinstance(value, str):
        return {value} if value else set()
    if isinstance(value, Mapping):
        value = value.values()
    if isinstance(value, Iterable):
        return {item for item in value if _valid_id(item)}
    return set()


def _tenant_scope(user_id, explicit_tenant=None):
    """Return the user's known tenant scope, or None when unconstrained."""
    scope = _tenant_values(explicit_tenant)
    if scope:
        return scope

    record = _record_for(user_id)
    scope = _tenant_values(record.get("tenant") or record.get("tenant_id"))
    if scope:
        return scope
    scope = _tenant_values(record.get("tenants"))
    if scope:
        return scope

    if isinstance(USER_TENANTS, Mapping):
        scope = _tenant_values(USER_TENANTS.get(user_id))
        if scope:
            return scope

    if isinstance(ADMIN_TENANTS, Mapping):
        scope = _tenant_values(ADMIN_TENANTS.get(user_id))
        if scope:
            return scope

    if isinstance(ADMINS, Mapping):
        scope = _tenant_values(ADMINS.get(user_id))
        if scope:
            return scope

    return None


def _is_admin(user_id, explicit_role=None):
    role = _role_for(user_id, explicit_role)
    if isinstance(role, str) and role.strip().lower() in ADMIN_ROLES:
        return True

    record = _record_for(user_id)
    if record.get("is_admin") is True or record.get("admin") is True:
        return True

    if isinstance(ADMINS, Mapping):
        return user_id in ADMINS and ADMINS.get(user_id) is not False
    if isinstance(ADMINS, (set, frozenset, list, tuple)):
        return user_id in ADMINS
    return False


def _authorize(user, doc_id, write=False):
    user_id, explicit_role, explicit_tenant = _principal(user)
    if not _valid_id(user_id) or not _valid_id(doc_id):
        return False

    doc = DOCS.get(doc_id) if isinstance(DOCS, Mapping) else None
    if not isinstance(doc, Mapping):
        return False
    if doc.get("deleted") or doc.get("is_deleted"):
        return False

    owner = doc.get("owner")
    tenant = doc.get("tenant")
    if not _valid_id(owner) or not _valid_id(tenant):
        return False

    scope = _tenant_scope(user_id, explicit_tenant)
    if scope is not None and tenant not in scope:
        return False

    if user_id == owner:
        return True

    if _is_admin(user_id, explicit_role):
        return True

    return False


def can_read(user, doc_id):
    with _LOCK:
        return _authorize(user, doc_id, write=False)


def can_write(user, doc_id):
    with _LOCK:
        return _authorize(user, doc_id, write=True)


def can_admin(user, tenant=None):
    user_id, explicit_role, explicit_tenant = _principal(user)
    if not _valid_id(user_id):
        return False
    if not _is_admin(user_id, explicit_role):
        return False
    if tenant is None:
        return True
    if not _valid_id(tenant):
        return False

    scope = _tenant_scope(user_id, explicit_tenant)
    return scope is None or tenant in scope


def update_doc(user, doc_id, fields):
    if not isinstance(fields, Mapping):
        return False

    with _LOCK:
        if not _authorize(user, doc_id, write=True):
            return False

        changes = dict(fields)
        if any(not _valid_id(key) for key in changes):
            return False
        if any(
            key in IMMUTABLE_FIELDS or key not in UPDATABLE_FIELDS
            for key in changes
        ):
            return False

        DOCS[doc_id].update(changes)
        return True

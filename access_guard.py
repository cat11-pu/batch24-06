DOCS = {
    "doc-alice": {"owner": "alice", "tenant": "t1", "deleted": False, "title": "alice"},
    "doc-bob": {"owner": "bob", "tenant": "t1", "deleted": False, "title": "bob"},
    "doc-carol": {"owner": "carol", "tenant": "t2", "deleted": True, "title": "carol"},
}


def can_read(user, doc_id):
    return doc_id in DOCS


def can_write(user, doc_id):
    return doc_id in DOCS


def can_admin(user, tenant=None):
    return True


def update_doc(user, doc_id, fields):
    if doc_id not in DOCS:
        return False
    DOCS[doc_id].update(fields)
    return True

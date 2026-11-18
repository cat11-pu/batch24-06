import copy

import pytest

import access_guard as ag

BASE = {
    "doc-alice": {"owner": "alice", "tenant": "t1", "deleted": False, "title": "alice"},
    "doc-bob": {"owner": "bob", "tenant": "t1", "deleted": False, "title": "bob"},
    "doc-carol": {"owner": "carol", "tenant": "t2", "deleted": True, "title": "carol"},
}


@pytest.fixture(autouse=True)
def clean_docs():
    ag.DOCS.clear()
    ag.DOCS.update(copy.deepcopy(BASE))


def test_1_other_user_cannot_read():
    assert ag.can_read("bob", "doc-alice") is False


def test_2_cross_tenant_cannot_read():
    assert ag.can_read("carol", "doc-alice") is False


def test_3_deleted_document_cannot_be_read():
    assert ag.can_read("carol", "doc-carol") is False


def test_4_other_user_cannot_write():
    assert ag.can_write("bob", "doc-alice") is False


def test_5_cross_tenant_cannot_write():
    assert ag.can_write("carol", "doc-alice") is False


def test_6_deleted_document_cannot_be_written():
    assert ag.can_write("carol", "doc-carol") is False


def test_7_normal_user_is_not_admin():
    assert ag.can_admin("bob") is False


def test_8_empty_user_cannot_read():
    assert ag.can_read("", "doc-alice") is False


def test_9_none_user_cannot_read():
    assert ag.can_read(None, "doc-alice") is False


def test_10_other_user_cannot_update():
    assert ag.update_doc("bob", "doc-alice", {"title": "hacked"}) is False


def test_11_update_cannot_change_owner():
    ag.update_doc("alice", "doc-alice", {"owner": "bob"})
    assert ag.DOCS["doc-alice"]["owner"] == "alice"


def test_12_update_cannot_change_tenant():
    ag.update_doc("alice", "doc-alice", {"tenant": "t9"})
    assert ag.DOCS["doc-alice"]["tenant"] == "t1"


def test_13_update_rejects_unknown_fields():
    ag.update_doc("alice", "doc-alice", {"unknown": "x"})
    assert "unknown" not in ag.DOCS["doc-alice"]


def test_14_deleted_document_cannot_be_updated():
    assert ag.update_doc("carol", "doc-carol", {"title": "x"}) is False


def test_15_admin_is_scoped_to_tenant():
    assert ag.can_admin("bob", "t2") is False

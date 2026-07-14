from __future__ import annotations

from contextlib import nullcontext
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from denilicense.domain import InvalidError
from denilicense.store import AdminActivationListFilter, Store

NOW = datetime(2026, 7, 12, tzinfo=UTC)


class Result:
    def __init__(self, *, one=None, all_=None):
        self.one = one
        self.all = [] if all_ is None else all_

    def fetchone(self):
        return self.one

    def fetchall(self):
        return self.all


class Connection:
    def __init__(self, result):
        self.result = result
        self.sql = ""
        self.params = None

    def execute(self, sql, params=None):
        self.sql = " ".join(str(sql).split())
        self.params = params
        return self.result


class ScriptedConnection:
    def __init__(self, *results):
        self.results = list(results)

    def execute(self, _sql, _params=None):
        return self.results.pop(0)


class Pool:
    def __init__(self, connection):
        self.value = connection

    def connection(self):
        return nullcontext(self.value)


def test_admin_activation_list_returns_pseudonymous_device_context():
    activation_id = uuid4()
    license_id = uuid4()
    serial = uuid4()
    owner_id = uuid4()
    thumbprint = bytearray(range(32))
    row = {
        "id": activation_id,
        "license_id": license_id,
        "license_serial": serial,
        "product_code": "DESKTOP",
        "owner_user_id": owner_id,
        "owner_email": "customer@example.com",
        "device_key_thumbprint": memoryview(thumbprint),
        "label": "Design workstation",
        "state": "active",
        "activated_at": NOW - timedelta(days=3),
        "last_seen_at": NOW,
        "lease_expires_at": NOW + timedelta(hours=1),
        "deactivated_at": None,
    }
    connection = Connection(Result(all_=[row]))
    store = Store(Pool(connection))

    items = store.list_admin_activations(
        AdminActivationListFilter(
            license_id=license_id,
            owner_normalized_email="customer@example.com",
            product_code="DESKTOP",
            state="active",
            label="workstation",
            device_key_thumbprint=bytes(thumbprint),
            limit=25,
        )
    )

    assert len(items) == 1
    assert items[0].device_key_thumbprint == bytes(thumbprint)
    assert type(items[0].device_key_thumbprint) is bytes
    assert items[0].license_serial == serial
    assert items[0].owner_email == "customer@example.com"
    assert "JOIN licenses" in connection.sql
    assert "ORDER BY a.activated_at DESC, a.id DESC LIMIT" in connection.sql
    assert connection.params[-1] == 25


def test_per_license_activation_converts_driver_buffer_and_includes_deactivation_time():
    activation_id = uuid4()
    license_id = uuid4()
    deactivated_at = NOW - timedelta(hours=1)
    connection = ScriptedConnection(
        Result(one={"exists": True}),
        Result(
            all_=[
                {
                    "id": activation_id,
                    "license_id": license_id,
                    "device_key_thumbprint": memoryview(b"t" * 32),
                    "label": "Retired laptop",
                    "state": "deactivated",
                    "activated_at": NOW - timedelta(days=30),
                    "last_seen_at": NOW - timedelta(days=2),
                    "lease_expires_at": NOW - timedelta(days=1),
                    "deactivated_at": deactivated_at,
                }
            ]
        ),
    )

    activation = Store(Pool(connection)).list_activations(license_id)[0]

    assert activation.device_key_thumbprint == b"t" * 32
    assert type(activation.device_key_thumbprint) is bytes
    assert activation.deactivated_at == deactivated_at


def test_admin_activation_filters_reject_invalid_device_identifiers():
    store = Store(Pool(Connection(Result(all_=[]))))

    with pytest.raises(InvalidError, match="thumbprint"):
        store.list_admin_activations(AdminActivationListFilter(device_key_thumbprint=b"short"))


def test_dashboard_summary_maps_all_aggregate_counts():
    names = (
        "total_licenses",
        "active_licenses",
        "suspended_licenses",
        "revoked_licenses",
        "claimed_licenses",
        "unclaimed_licenses",
        "total_activations",
        "active_activations",
        "deactivated_activations",
        "current_leases",
        "expiring_licenses_30_days",
        "total_users",
        "active_users",
        "total_products",
        "active_products",
    )
    row = {name: index for index, name in enumerate(names, start=1)}
    connection = Connection(Result(one=row))

    summary = Store(Pool(connection)).dashboard_summary()

    assert summary.total_licenses == 1
    assert summary.current_leases == 10
    assert summary.active_products == 15
    assert "clock_timestamp()+interval '30 days'" in connection.sql


def test_list_issuers_can_filter_status_without_exposing_private_material():
    row = {
        "key_id": "k" * 43,
        "issuer": "com.example.offline",
        "public_key": memoryview(b"p" * 32),
        "status": "active",
        "not_before": NOW,
        "not_after": None,
        "created_at": NOW,
    }
    connection = Connection(Result(all_=[row]))

    issuers = Store(Pool(connection)).list_issuers("active", 20)

    assert issuers[0].public_key == b"p" * 32
    assert connection.params == ("active", "active", 20)
    assert "ORDER BY created_at DESC, key_id DESC" in connection.sql

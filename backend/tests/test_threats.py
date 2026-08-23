"""ThreatLens AI — Threat Endpoint Tests"""

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from tests.conftest import auth_headers, create_test_user, create_test_threat
from app.models.threat import ThreatSeverity, ThreatStatus


@pytest.mark.asyncio
class TestThreatCRUD:
    async def test_create_threat(self, client: AsyncClient, db_session: AsyncSession):
        user = await create_test_user(db_session)
        resp = await client.post(
            "/api/v1/threats",
            json={
                "title": "Ransomware activity on endpoint",
                "severity": "critical",
                "threat_type": "ransomware",
                "source_ip": "10.0.0.50",
                "affected_asset": "workstation-42",
            },
            headers=auth_headers(user),
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["severity"] == "critical"
        assert data["status"] == "open"
        assert data["reported_by_id"] == user.id

    async def test_list_threats(self, client: AsyncClient, db_session: AsyncSession):
        user = await create_test_user(db_session)
        await create_test_threat(db_session, user.id, ThreatSeverity.HIGH)
        await create_test_threat(db_session, user.id, ThreatSeverity.CRITICAL)

        resp = await client.get("/api/v1/threats", headers=auth_headers(user))
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 2
        assert len(data["items"]) == 2

    async def test_filter_by_severity(self, client: AsyncClient, db_session: AsyncSession):
        user = await create_test_user(db_session)
        await create_test_threat(db_session, user.id, ThreatSeverity.HIGH)
        await create_test_threat(db_session, user.id, ThreatSeverity.LOW)

        resp = await client.get("/api/v1/threats?severity=high", headers=auth_headers(user))
        assert resp.status_code == 200
        assert resp.json()["total"] == 1

    async def test_get_threat_by_id(self, client: AsyncClient, db_session: AsyncSession):
        user = await create_test_user(db_session)
        threat = await create_test_threat(db_session, user.id)

        resp = await client.get(f"/api/v1/threats/{threat.id}", headers=auth_headers(user))
        assert resp.status_code == 200
        assert resp.json()["id"] == threat.id

    async def test_get_threat_not_found(self, client: AsyncClient, db_session: AsyncSession):
        user = await create_test_user(db_session)
        resp = await client.get("/api/v1/threats/99999", headers=auth_headers(user))
        assert resp.status_code == 404

    async def test_update_threat_status(self, client: AsyncClient, db_session: AsyncSession):
        user = await create_test_user(db_session)
        threat = await create_test_threat(db_session, user.id)

        resp = await client.patch(
            f"/api/v1/threats/{threat.id}",
            json={"status": "investigating"},
            headers=auth_headers(user),
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "investigating"

    async def test_resolve_threat(self, client: AsyncClient, db_session: AsyncSession):
        user = await create_test_user(db_session)
        threat = await create_test_threat(db_session, user.id)

        resp = await client.patch(
            f"/api/v1/threats/{threat.id}",
            json={"is_resolved": True},
            headers=auth_headers(user),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["is_resolved"] is True
        assert data["resolved_at"] is not None

    async def test_delete_threat_requires_admin(self, client: AsyncClient, db_session: AsyncSession):
        user = await create_test_user(db_session, is_admin=False)
        threat = await create_test_threat(db_session, user.id)

        resp = await client.delete(f"/api/v1/threats/{threat.id}", headers=auth_headers(user))
        assert resp.status_code == 403

    async def test_delete_threat_as_admin(self, client: AsyncClient, db_session: AsyncSession):
        admin = await create_test_user(db_session, email="admin@threatlens.ai", username="admin", is_admin=True)
        threat = await create_test_threat(db_session, admin.id)

        resp = await client.delete(f"/api/v1/threats/{threat.id}", headers=auth_headers(admin))
        assert resp.status_code == 204


@pytest.mark.asyncio
class TestThreatStats:
    async def test_stats_endpoint(self, client: AsyncClient, db_session: AsyncSession):
        user = await create_test_user(db_session)
        await create_test_threat(db_session, user.id, ThreatSeverity.CRITICAL)
        await create_test_threat(db_session, user.id, ThreatSeverity.HIGH)

        resp = await client.get("/api/v1/threats/stats", headers=auth_headers(user))
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 2
        assert data["critical"] == 1
        assert "severity_breakdown" in data

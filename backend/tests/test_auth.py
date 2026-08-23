"""ThreatLens AI — Authentication Endpoint Tests"""

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from tests.conftest import auth_headers, create_test_user


@pytest.mark.asyncio
class TestAuthRegister:
    async def test_register_success(self, client: AsyncClient):
        resp = await client.post("/api/v1/auth/register", json={
            "email": "new@threatlens.ai",
            "username": "newuser",
            "password": "SecurePass123",
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["email"] == "new@threatlens.ai"
        assert "hashed_password" not in data

    async def test_register_duplicate_email(self, client: AsyncClient, db_session: AsyncSession):
        await create_test_user(db_session)
        resp = await client.post("/api/v1/auth/register", json={
            "email": "analyst@threatlens.ai",
            "username": "another",
            "password": "SecurePass123",
        })
        assert resp.status_code == 409

    async def test_register_weak_password(self, client: AsyncClient):
        resp = await client.post("/api/v1/auth/register", json={
            "email": "weak@threatlens.ai",
            "username": "weakuser",
            "password": "password",  # no uppercase, no digit
        })
        assert resp.status_code == 422


@pytest.mark.asyncio
class TestAuthLogin:
    async def test_login_success(self, client: AsyncClient, db_session: AsyncSession):
        await create_test_user(db_session)
        resp = await client.post("/api/v1/auth/login", data={
            "username": "analyst",
            "password": "SecurePass123",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"

    async def test_login_wrong_password(self, client: AsyncClient, db_session: AsyncSession):
        await create_test_user(db_session)
        resp = await client.post("/api/v1/auth/login", data={
            "username": "analyst",
            "password": "WrongPassword123",
        })
        assert resp.status_code == 401

    async def test_login_with_email(self, client: AsyncClient, db_session: AsyncSession):
        """Login should work with email address in the username field."""
        await create_test_user(db_session)
        resp = await client.post("/api/v1/auth/login", data={
            "username": "analyst@threatlens.ai",
            "password": "SecurePass123",
        })
        assert resp.status_code == 200


@pytest.mark.asyncio
class TestAuthMe:
    async def test_get_current_user(self, client: AsyncClient, db_session: AsyncSession):
        user = await create_test_user(db_session)
        resp = await client.get("/api/v1/auth/me", headers=auth_headers(user))
        assert resp.status_code == 200
        assert resp.json()["id"] == user.id

    async def test_unauthenticated(self, client: AsyncClient):
        resp = await client.get("/api/v1/auth/me")
        assert resp.status_code == 401


@pytest.mark.asyncio
class TestAuthRefresh:
    async def test_refresh_tokens(self, client: AsyncClient, db_session: AsyncSession):
        await create_test_user(db_session)
        login_resp = await client.post("/api/v1/auth/login", data={
            "username": "analyst", "password": "SecurePass123"
        })
        refresh_token = login_resp.json()["refresh_token"]

        resp = await client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})
        assert resp.status_code == 200
        assert "access_token" in resp.json()

    async def test_refresh_with_access_token_fails(self, client: AsyncClient, db_session: AsyncSession):
        await create_test_user(db_session)
        login_resp = await client.post("/api/v1/auth/login", data={
            "username": "analyst", "password": "SecurePass123"
        })
        # Attempting to refresh with an access token should be rejected
        access_token = login_resp.json()["access_token"]
        resp = await client.post("/api/v1/auth/refresh", json={"refresh_token": access_token})
        assert resp.status_code == 401

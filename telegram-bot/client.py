"""
Thin async HTTP client over GokuShield's existing Flask API. This does not
reimplement any scanning, chat, or remediation logic — it calls the real
backend endpoints so the bot and website always share one source of truth.
"""
import httpx


class GokuShieldClient:
    def __init__(self, base_url: str, timeout: float = 30.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._admin_token: str | None = None

    async def start_free_audit(self, email: str, target: str) -> dict:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                f"{self.base_url}/api/free-audit/audit",
                json={"email": email, "target": target},
            )
            return resp.json()

    async def get_audit_result(self, scan_id: int) -> dict:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.get(f"{self.base_url}/api/free-audit/audit/{scan_id}")
            return resp.json()

    async def chat(self, message: str, history: list) -> dict:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                f"{self.base_url}/api/chatbot/chat",
                json={"message": message, "history": history},
            )
            return resp.json()

    async def _admin_login(self, email: str, password: str) -> str:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                f"{self.base_url}/api/auth/login",
                json={"email": email, "password": password},
            )
            data = resp.json()
            token = data.get("access_token")
            if not token:
                raise RuntimeError(f"Admin login failed: {data}")
            return token

    async def _admin_request(self, admin_email: str, admin_password: str, method: str, path: str, **kwargs) -> dict:
        """
        Makes an authenticated admin request, logging in once and reusing
        the token, and transparently re-logging-in on a 401 (expired
        token) rather than asking the operator to paste a fresh JWT
        into an env var periodically.
        """
        for attempt in range(2):
            if not self._admin_token:
                self._admin_token = await self._admin_login(admin_email, admin_password)

            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.request(
                    method, f"{self.base_url}{path}",
                    headers={"Authorization": f"Bearer {self._admin_token}"},
                    **kwargs,
                )
            if resp.status_code == 401 and attempt == 0:
                self._admin_token = None  # force re-login on next loop
                continue
            return resp.json()
        return {"error": "Admin authentication failed"}

    async def list_pending_remediations(self, admin_email: str, admin_password: str) -> dict:
        return await self._admin_request(
            admin_email, admin_password, "GET", "/api/admin/remediations",
            params={"status": "pending"},
        )

    async def review_remediation(self, admin_email: str, admin_password: str, action_id: int, status: str) -> dict:
        return await self._admin_request(
            admin_email, admin_password, "PUT", f"/api/admin/remediations/{action_id}",
            json={"status": status},
        )


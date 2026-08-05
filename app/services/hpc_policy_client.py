import httpx

HPC_COMPUTE_SERVICES = {"tes", "toolserver", "workbench"}


class HPCPolicyClient:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.http = httpx.AsyncClient(timeout=5)

    def is_compute_service(self, service: str) -> bool:
        return service in HPC_COMPUTE_SERVICES

    async def evaluate(
        self,
        user_id: str,
        service: str,
        trace_id: str = "",
        cpu_hours: float = 0,
        gpu_hours: float = 0,
        gpus: int = 0,
        memory_gb: int = 0,
        roles: list | None = None,
    ) -> dict:
        payload = {
            "user_id": user_id,
            "cpu_hours": cpu_hours,
            "gpu_hours": gpu_hours,
            "gpus": gpus,
            "memory_gb": memory_gb,
            "partition": "gpu" if gpus > 0 else "cpu",
            # PR12: /jobs/evaluate now actually checks roles (previously
            # always approved regardless) -- forward what AuthMiddleware
            # already put on request.state.user instead of leaving it
            # unset (defaulting to no roles at all on the HPC engine side).
            "roles": roles or [],
        }
        headers = {
            "X-Internal-Service": "gateway",
            "X-Trace-Id": trace_id,
            "X-User-Id": user_id,
        }

        for attempt in range(2):
            try:
                res = await self.http.post(
                    f"{self.base_url}/jobs/evaluate",
                    json=payload,
                    headers=headers,
                    timeout=5,
                )
                return res.json()
            except httpx.TimeoutException:
                if attempt == 0:
                    continue
                return {"allow": False, "reason": "hpc_timeout"}
            except Exception:
                return {"allow": False, "reason": "hpc_error"}

        return {"allow": False, "reason": "hpc_unavailable"}

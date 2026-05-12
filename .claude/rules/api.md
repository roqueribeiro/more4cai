---
description: Convenções para FastAPI routers, auth e validação em orchestrator/api/
paths:
  - "orchestrator/api/**"
  - "orchestrator/main.py"
---

# Convenções da API REST

Stack: FastAPI + Pydantic v2 + SQLModel + arq pra fila. Auth: token via header `X-API-Token`.

## Padrão de router

Todo router fica em `orchestrator/api/routers/<dominio>.py` e segue:

```python
from fastapi import APIRouter
from orchestrator.api.deps import SessionDep, TokenDep

router = APIRouter(prefix="/dominio", tags=["dominio"])

class FooIn(BaseModel): ...
class FooOut(BaseModel): ...

@router.post("", response_model=FooOut, status_code=201)
async def create_foo(
    body: FooIn,
    session: SessionDep,   # injeta AsyncSession
    _token: TokenDep,      # FORÇA auth
) -> FooOut: ...
```

**`_token: TokenDep` é OBRIGATÓRIO em todo endpoint** (até `/health` que poderia ser livre — mantemos consistente). Nunca remover sem discutir.

Registrar no `orchestrator/main.py`:

```python
from orchestrator.api.routers import dominio as dominio_router
app.include_router(dominio_router.router)
```

## Validação de input

- Pydantic v2 schemas em `routers/<dominio>.py` (perto do uso)
- Modelos de DB em `orchestrator/persistence/models.py`
- NUNCA expor `*Row` (modelos de DB) diretamente — sempre `*Out` derivado

## Async patterns

- Endpoints `async def` SEMPRE
- Sessões DB injetadas via `SessionDep` (`get_session()` async generator)
- arq pool criado on-demand: `pool = await create_pool(_redis_settings())` — não cachear globalmente em request handler
- `await session.commit()` antes de retornar a response

## Status codes

- POST que cria → `201 Created`
- POST que enfileira async job → `202 Accepted`
- GET → `200 OK`
- 404 sem entidade → `HTTPException(404, "X não encontrado")` (PT-BR)
- 401 sem token → automatic via dep
- 403 violação de policy do engagement → `HTTPException(403, ...)` com mensagem clara

## Modificações que requerem cuidado

**Mudar `deps.py:require_token`** muda postura de auth do projeto inteiro. Discutir antes. Nunca permitir endpoint sem token (a não ser `/health`, e mesmo esse mantém pra consistência).

**Mudar resposta de endpoint existente** quebra clientes externos (DefectDojo, scripts, IAs patcher consumindo `/ai-bundle`). Versionar via `/v2/...` ou alias.

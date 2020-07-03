# python3
from typing import Any, List

class Cursor:
    _rows: List[Any]
    async def execute(self, query: str, arg: Any = None) -> None: ...
    async def __aenter__(self) -> Any: ...
    async def __aexit__(self, *exc: object) -> None: ...

class DictCursor(Cursor):
    ...

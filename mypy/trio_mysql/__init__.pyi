# python3
from typing import Any, Type, TypeVar, Generic, Tuple, Iterator, List, Awaitable
import trio_mysql.cursors

class Transaction:
    async def __aenter__(self) -> None: ...
    async def __aexit__(self, *exc: object) -> None: ...

class Connection:
    async def connect(self) -> None:
        ...

    def cursor(self) -> trio_mysql.cursors.Cursor: ...
    def transaction(self) -> Transaction: ...


def connect(*args: Any, **kwargs: Any) -> Connection: ...

TT = TypeVar('TT')
class TCursor(Generic[TT], trio_mysql.cursors.Cursor):
    _rows: List[TT]

    async def fetchone(self) -> TT: ...
    def __iter__(self) -> Iterator[TT]: ...

    async def __aenter__(self) -> TCursor[TT]: ...
    async def __aexit__(self, *exc: object) -> None: ...


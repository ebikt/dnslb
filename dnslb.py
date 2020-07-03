#!/usr/bin/python3
import re
import socket
import time
import sys, os
import traceback

sys.path.insert(0, os.path.dirname(__file__) + '/lib')

import trio
import trio_mysql
import trio_mysql.cursors

from typing import List, Dict, Tuple, Any, Set, Optional, TypeVar, Type, Union

MYPY=False
if MYPY:
    from typing_extensions import TypedDict


RECORDS=[
    {
        "type":  "A",
        "name": "dbrep.gm",
        "dest": ["gmsql3.cent", "gmsql4.cent"], #these are resolved to get resulting machines
        "interval": 5, # 15 FIXME
        "shift": 3, #check is executed at time.time() % inteval == shift
        "check":["/usr/bin/mysql", "-h", "%(address)s", "-u", "healthcheck", "-phealthcheck", "-Bse", "select 'GOOD';"],
        "timeout": 5, #if (timeout + dns_timeout) >= interval, then rate of checks may be halved (or even slower)
        "expect": r'(^|\n)GOOD(\n|$)',
        "fallback": "gmsql1.cent",
    }
]

DNS_TIMEOUT=5
TTL=1

SQL_CONFIGURATION=dict(
    domain_name     = "dnslb",
    delete_unknowns = True,
    database        = 'dns',
    unix_socket     = '/var/run/mysqld/mysqld.sock',
    charset         = 'utf8mb4',
    cursorclass     = trio_mysql.cursors.DictCursor,
)

T = TypeVar('T')
class ConfigExtractor: # {{{

    def __init__(self, config: Dict[str, object]) -> None:
        self._config = config

    def __contains__(self, key: str) -> bool:
        return key in self._config

    def _get(self, key: str, type: Type[T],  default: Optional[T] = None) -> T:
        if default is None:
            return self._config[key] # type: ignore
        else:
            return self._config.get(key, default) # type: ignore

    def _pop(self, key: str, type: Type[T],  default: Optional[T] = None) -> T:
        if default is None:
            return self._config.pop(key) # type: ignore
        else:
            return self._config.pop(key, default) # type: ignore

    def get(self, key: str, type: Type[T],  default: Optional[T] = None) -> T:
        return type(self._get(key, type, default)) # type: ignore

    def pop(self, key: str, type: Type[T],  default: Optional[T] = None) -> T:
        return type(self._pop(key, type, default)) # type: ignore

    def l_str(self, key: str, default: Optional[List[str]] = None) -> List[str]:
        v = self._get(key, List[str], default)
        return [ str(e) for e in v ]

    def float(self, key: str, default: Optional[float] = None) -> float:
        return self.get(key, float, default)

    def str(self, key: str, default: Optional[str] = None) -> str:
        return self.get(key, str, default)
# }}}


class Records: # {{{
    def __init__(self, rc: "RecordController", results: Dict[str, bool]) -> None:
        self.type      = rc.type
        self.name      = rc.name
        self.ttl       = TTL
        self.timestamp = int(time.time())
        self.results   = results
# }}}

DNSResult = Tuple[str, List[str]]

class RecordController: # {{{
    results: Dict[str, bool]
    type: str
    name: str
    proto: int
    family: socket.AddressFamily

    def __init__(self, config: ConfigExtractor, logger: "Logger"): # {{{
        self.type   = config.str('type')
        self.family = {"A":socket.AF_INET, "AAAA":socket.AF_INET6}[self.type]
        if 'proto' in config:
            self.proto = getattr(socket, "IPPROTO_" + config.str('proto').lower())
            assert isinstance(self.proto, int)
        else:
            self.proto = socket.IPPROTO_TCP
        if 'socktype' in config:
            self.socktype:int = socket.SocketKind(config.str('socktype'))
        else:
            self.socktype = {
                socket.IPPROTO_TCP: socket.SOCK_STREAM,
                socket.IPPROTO_UDP: socket.SOCK_DGRAM,
            }.get(self.proto, 0)
        self.name        = config.str('name')

        self.dest        = config.l_str('dest')
        self.interval    = config.float('interval')
        self.shift       = config.float('shift')
        self.check       = config.l_str('check')
        self.timeout     = config.float('timeout')
        self.dns_timeout = config.float('dns_timeout', DNS_TIMEOUT)
        self.regex       = re.compile(config.str('expect'))
        self.fallback    = config.str('fallback', '')

        self.logger = logger
        logprefix = self.logprefix = "%s,%s" % (self.name, self.type)
        logger.info(logprefix, "dest: %r" % (self.dest,))
        logger.info(logprefix, "at time %% %.2f == %.2f" % (self.interval, self.timeout))
        logger.info(logprefix, "check command: %r" % (self.check,))
        logger.info(logprefix, "check timeout: %.2f, dns timeout %.2f, check.regex:%s" %
            (self.timeout, self.dns_timeout, config.str('expect')))
    # }}}

    async def run_check(self, address: str) -> None: # {{{
        fmt = { "address": address}
        cmdline = [ x % fmt for x in self.check ]
        logprefix = "%s,%s" % (self.logprefix, address)
        try:
            self.logger.debug(logprefix, "launching %r" % (cmdline,))
            with trio.fail_after(self.timeout):
                result = await trio.run_process(cmdline, capture_stdout=True)
            if self.regex.search(result.stdout.decode('utf-8', 'ignore')):
                self.logger.debug(logprefix, "destination OK")
                self.results[address] = True
            else:
                self.logger.debug(logprefix, "destination failed")
        except Exception as e:
            self.logger.warning(logprefix, "check error: %s" % (e,))
            pass
    # }}}

    async def resolve_one(self, queue, dest): # type: (trio.MemorySendChannel[DNSResult], str) -> None # {{{
        logprefix = "%s:%s" % (self.logprefix, dest)
        self.logger.debug(logprefix, "issuing getaddrinfo()")
        try:
            aresult = await trio.socket.getaddrinfo(dest, 0, self.family, self.socktype, self.proto, 0) # type: ignore
            result: List[str] = [ r[4][0] for r in aresult ] # type: ignore
            self.logger.debug(logprefix, "getaddrinfo returned %d results" % (len(result),))
            await queue.send( (dest, result) )
        except trio.Cancelled as e:
            self.logger.warning(logprefix, "getaddrinfo cancelled: %s" % (e,))
            raise
        except Exception as e:
            self.logger.error(logprefix, "getaddrinfo failed: %s" % (e,))
            pass
    # }}}

    async def resolve_all(self, queue): # type: (trio.MemorySendChannel[DNSResult]) -> None # {{{
        async with queue:
            self.logger.debug(self.logprefix, "starting to resolve entries (timeout: %.2f)" % (self.dns_timeout,))
            with trio.move_on_after(self.dns_timeout):
                try:
                    async with trio.open_nursery() as nursery:
                        for dest in self.dest:
                            self.logger.debug(self.logprefix, "start soon: resolve %r" % (dest,))
                            nursery.start_soon(self.resolve_one, queue, dest)
                except Exception as e:
                    self.logger.debug(self.logprefix, "exc %s" % (e,))
                    raise
            self.logger.debug(self.logprefix, "all entries resolved")
    # }}}

    async def process_resolved(self, queue, nursery): # type: (trio.MemoryReceiveChannel[DNSResult], trio.Nursery) -> None # {{{
        self.results = {}
        async with queue:
            async for query, result in queue:
                for address in result:
                    if address not in self.results:
                        self.logger.debug(self.logprefix, " %s -> %s, Queueing check." % (query, address))
                        self.results[address] = False
                        nursery.start_soon(self.run_check, address)
                    else:
                        self.logger.debug(self.logprefix, " %s -> %s, Ignoring duplicit result." % (query, address))
    # }}}

    async def run(self, sqlqueue): # type: (trio.MemorySendChannel[Records]) -> None # {{{
        while True:
            sleep = self.interval - (time.time() - self.shift) % self.interval
            self.logger.debug(self.logprefix, "waiting %.2f seconds" % (sleep,))
            await trio.sleep(sleep)
            try:
                qin:  trio.MemorySendChannel[DNSResult]
                qout: trio.MemoryReceiveChannel[DNSResult]
                qin, qout = trio.open_memory_channel(len(self.dest))
                async with trio.open_nursery() as nursery:
                    nursery.start_soon(self.resolve_all, qin)
                    nursery.start_soon(self.process_resolved, qout, nursery)

                any_ok = False
                for rv in self.results.values():
                    if rv: any_ok = True

                if not any_ok:
                    if self.fallback:
                        self.logger.warning(self.logprefix, "All checks failed, resolving fallback.")
                        try:
                            aresult = await trio.socket.getaddrinfo(self.fallback, 0, self.family, self.socktype, self.proto, 0) # type: ignore
                            result: List[str] = [ r[4][0] for r in aresult ] # type: ignore
                        except Exception as e:
                            self.logger.warning(self.logprefix, "fallback getaddrinfo failed: %s" % (e,))
                            result = []
                        if len(result) == 0:
                            self.logger.warning(self.logprefix, "Cannot resolve fallback. Deleting entry.")
                        for r in result:
                            self.logger.debug(self.logprefix, "Adding fallback entry %s" % (r,))
                            self.results[r] = True
                    else:
                        self.logger.warning(self.logprefix, "All checks failed, no fallback provided, deleting entry.")
                self.logger.debug(self.logprefix, "Sending result")
                await sqlqueue.send(Records(self, self.results))
                self.results = None # type: ignore # Disable editting of self.results after passed away
            except trio.Cancelled:
                raise
            except Exception:
                self.logger.error(self.logprefix, "Error occured %s" % (traceback.format_exc(),))
                pass
    # }}}
# }}}

if MYPY:
    C_id         = TypedDict('C_id',         {"id": int})
    C_id_content = TypedDict('C_id_content', {"id": int,   "content": str})
    C_name_type  = TypedDict('C_name_type',  {"name": str, "type": str})

class SqlController: # {{{
    domain_id: int

    def __init__(self, config: ConfigExtractor, logger: "Logger") -> None:
        self.delete_unknowns:bool = config.pop('delete_unknowns', bool)
        self.domain_name:str      = config.pop('domain_name', str)
        self.conn                 = trio_mysql.connect(**config._config)
        self.domain_name = '.' + self.domain_name.lstrip('.')
        self.logger               = logger

    async def exl(self, cursor: trio_mysql.cursors.Cursor, query: str, arg: Optional[object]=None) -> None: #{{{ log and execute query
        if arg is None:
            self.logger.debug("sql", "Executing `%s`" % (query,))
            await cursor.execute(query)
        else:
            assert isinstance(arg, tuple)
            self.logger.debug("sql", "Executing `%s` on %s" % (query, arg))
            await cursor.execute(query, arg)
        if cursor._rows: # type: ignore
            self.logger.debug("sql", "  Returned %d rows" % (len(cursor._rows))) # type: ignore
            for row in cursor._rows: # type: ignore
                self.logger.debug("sql", "  %r" % (row,)) # type: ignore
    # }}}

    async def prepare(self) -> None: # {{{ asynchronous init
        await self.conn.connect()
        async with self.conn.cursor() as cursor: # type: trio_mysql.TCursor[C_id]
            await self.exl(cursor, "SELECT id FROM domains WHERE name = %s", (self.domain_name[1:],))
            row = await cursor.fetchone()
            self.domain_id = row['id']
    # }}}

    async def delete_unkown_entries(self, known_set: Set[Tuple[str, str]]) -> None: # {{{
        assert self.domain_name.startswith('.')
        unknown_set = set()
        async with self.conn.transaction():
            async with self.conn.cursor() as cursor: # type: trio_mysql.TCursor[C_name_type]
                await self.exl(cursor, "SELECT r.name, r.type FROM records r WHERE domain_id = %s AND type in ('A', 'AAAA')", (self.domain_id,))
                for row in cursor: #this cursor is prefetched (buffered), no need to async
                    if row['name'].endswith(self.domain_name):
                        entry = (row['name'][:-len(self.domain_name)], row['type'])
                        if entry not in known_set:
                            unknown_set.add( (row['name'], row['type'], self.domain_id) )
            if len(unknown_set):
                if self.delete_unkown_entries:
                    self.logger.warning("sql", "Deleting unknown entries: %r" % (unknown_set))
                    for unk in unknown_set:
                        await self.exl(cursor, "DELETE FROM records WHERE name = %s, type = %s, domain_id = %s", unk)
                else:
                    self.logger.warning("sql", "Keeping unknown entries: %r" % (unknown_set))
    # }}}

    async def update_records(self, records: Records) -> None: # {{{
        assert self.domain_name.startswith('.')
        name = records.name + self.domain_name
        now = int(records.timestamp)
        async with self.conn.transaction():
            async with self.conn.cursor() as cursor: # type: trio_mysql.TCursor[C_id_content]
                content_ids = {}
                delete_ids = set()
                await self.exl(cursor, "SELECT id, content FROM records WHERE name = %s AND type = %s AND domain_id = %s",
                    (name, records.type, self.domain_id))
                for row in cursor:
                    content = str(row['content'])
                    id = int(row['id'])
                    if content not in records.results or id in content_ids:
                        delete_ids.add(id)
                    else:
                        content_ids[content] = id
                for content, enabled in records.results.items():
                    disabled = 0 if enabled else 1
                    if content in content_ids:
                        await self.exl(cursor, "UPDATE records SET disabled = %s, last_lb_check = %s, ttl = %s WHERE id = %s",
                                (disabled, now, records.ttl, content_ids[content]))
                    else:
                        await self.exl(cursor, "INSERT INTO records(domain_id, name, type, content, ttl, disabled, last_lb_check)" +
                            " VALUES (%s, %s, %s, %s, %s, %s, %s)",
                            (self.domain_id, name, records.type, content, records.ttl, disabled, now))
                if len(delete_ids):
                    await self.exl(cursor, "DELETE FROM records WHERE id IN (" + ",".join(str(i) for i in delete_ids) + ")")
    # }}}
# }}}

class Logger: # {{{
    DEBUG=0
    INFO=1
    WARNING=2
    ERROR=3

    def debug(self, module: str, msg:str) -> None:
        self.msg(self.DEBUG, module, msg)

    def info(self, module: str, msg:str) -> None:
        self.msg(self.INFO, module, msg)

    def warning(self, module: str, msg:str) -> None:
        self.msg(self.WARNING, module, msg)

    def error(self, module: str, msg:str) -> None:
        self.msg(self.ERROR, module, msg)

    NAMES=['dbg','inf','wrn','err']
    COLORS=['30;1','32;1','33;1','31;1']
    COL_B='\x1b['
    COL_E='m'
    COL_R='0'
    COL_M='36'

    def __init__(self) -> None:
        self.COLORS = [ self.COL_B + x + self.COL_E for x in self.COLORS ]
        self.COL_R  = self.COL_B + self.COL_R + self.COL_E
        self.COL_M  = self.COL_B + self.COL_M + self.COL_E

    def msg(self, level: int, module: str, msg: str) -> None:
        sys.stderr.write('%s[%s]%s %s[%s]%s %s\n' % (
            self.COLORS[level], self.NAMES[level], self.COL_R,
            self.COL_M, module, self.COL_R,
            msg) )
# }}}

class Main: # {{{
    async def init(self) -> None: # {{{
        self.logger = Logger()

        self.rcs = []
        for r in RECORDS:
            self.rcs.append(RecordController(ConfigExtractor(r), self.logger))
        self.sql = SqlController(ConfigExtractor(SQL_CONFIGURATION), self.logger)
    # }}}

    async def run_record_controllers(self, queue): # type: (trio.MemorySendChannel[Records]) -> None # {{{
        async with queue:
            async with trio.open_nursery() as nursery:
                for rc in self.rcs:
                    nursery.start_soon(rc.run, queue)
        self.logger.warning('main', "Something happened, controllers nursery was terminated.")
    # }}}

    async def run_sql(self, queue): # type: (trio.MemoryReceiveChannel[Records]) -> None # {{{
        async with queue:
            async for records in queue:
                try:
                    await self.sql.update_records(records)
                except Exception as e:
                    self.logger.warning('main', 'SQL update failed: %s' % (e,))
                    raise
    # }}}

    async def main(self) -> None: # {{{
        await self.sql.prepare()
        await self.sql.delete_unkown_entries(set([(rc.name, rc.type) for rc in self.rcs]))
        sqlin:  trio.MemorySendChannel[Records]
        sqlout: trio.MemoryReceiveChannel[Records]
        sqlin, sqlout = trio.open_memory_channel(len(self.rcs))
        self.logger.debug("main", "Start loops.")
        async with trio.open_nursery() as nursery:
            nursery.start_soon(self.run_record_controllers, sqlin)
            nursery.start_soon(self.run_sql, sqlout)
        self.logger.debug("main", "Finish.")
    # }}}

async def main() -> None:
    m = Main()
    await m.init()
    await m.main()

trio.run(main)

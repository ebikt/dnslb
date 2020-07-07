#!/usr/bin/python3

import argparse
import enum
import json
import os
import re
import socket
import sys
import time
import toml
import traceback

from typing import List, Dict, Tuple, Any, Set, Optional, TypeVar, Type, Union, Iterator

sys.path.insert(0, os.path.dirname(__file__) + '/lib')

import trio
import trio_mysql
import trio_mysql.cursors

MYPY=False
if MYPY:
    from typing_extensions import TypedDict
T = TypeVar('T')

class ConfigError(Exception):
    pass

class MissingConfigError(ConfigError):
    pass

class ConfigExtractor: # {{{
    """ Class that ensures that configuration has proper type
        (raises ConfigError), no key is missing (raises MissingConfigError)
        and all keys were used by configuration consumer (i.e. they
        are known by application).

        usage:

        with ConfigExtractor(my_config_dict) as cfg:
            bool_value = cfg.bool('bool_key')
            str_list   = cfg.str_l('string_list_key')
            subsection = cfg.section('subsection')

        with subsection:
            subsection_str = cfg.str('some_key')
    """

    def __init__(self, config: Dict[str, object], section: str = '', default: Union[Dict[str, object],bool] = False) -> None: # {{{
        self._config = config
        if isinstance(default, bool):
            self._fake_default = default
        else:
            self._fake_default = False
            for key in default:
                self._config.setdefault(key, default[key])
        self._known: Set[str] = set()
        self._section = section
        self._current_key: Optional[str] = None
    # }}}

    # {{{ auxiliary functions, defining container like behaviour and context manager
    def __contains__(self, key: str) -> bool:
        self._current_key = key
        return key in self._config

    def __iter__(self) -> Iterator[str]:
        return iter(self._config)

    def __enter__(self) -> "ConfigExtractor":
        return self

    def __exit__(self, _t: object, e: BaseException, t: object) -> None:
        if isinstance(e, MissingConfigError):
            # pass exception
            return None
        if isinstance(e, Exception):
            # hide original exception, raise ConfigError
            self.reraise(e)
        if e is None:
            # raise exception about keys that were not used by configuration consumer
            self.raise_unknowns()
        return None

    _fakes: Dict[object, object] = {
        List[str]: [],
        Dict[str, object]: {},
    }

    def _get(self, key: str, type: Type[T],  default: Optional[T] = None) -> T:
        self._current_key = key
        self._known.add(key)
        if default is None:
            try:
                return self._config[key] # type: ignore
            except KeyError as e:
                if self._fake_default:
                    if type in self._fakes:
                        return self._fakes[type] # type: ignore
                    else:
                        return type()
                else:
                    raise MissingConfigError("Error when parsing section [%s]: missing key %r" % (self._section, key))
        else:
            return self._config.get(key, default) # type: ignore

    def reraise(self, e: Exception) -> None:
        raise ConfigError("Error when parsing key %r of [%s]: %s" % (self._current_key, self._section, e))

    def raise_unknowns(self) -> None:
        u: List[str] = list(set(self._config.keys()) - self._known)
        if len(u):
            u.sort()
            raise ConfigError("Error when parsing section [%s]: unknown keys: %s" % (self._section, u))
    # }}}

    def get(self, key: str, type: Type[T],  default: Optional[T] = None) -> T:
        """ getter that tries to convert value to specified type """
        return type(self._get(key, type, default)) # type: ignore

    def section(self, key: str, quote_name: bool = False, default: Union["ConfigExtractor", bool] = False) -> "ConfigExtractor":
        """ returns ConfigExtratror of subsection stored under specified key
            arguments:
                quote_name  should section name be quoted when printing errors?
                default     set this to True, to provide fake defaults when parsing.
                                This is useful when validating default section to ignore
                                missing keys.
                            set this to instance of default section, to provide default values
        """
        ret = self._get(key, Dict[str, object])
        if not isinstance(ret, dict):
            raise Exception("expecting section")
        if quote_name:
            key = json.dumps(key)
        if self._section != '':
            key = "%s.%s" % (self._section, key)
        return ConfigExtractor(ret, key, default if isinstance(default, bool) else default._config)

    def l_str(self, key: str, default: Optional[List[str]] = None) -> List[str]:
        """ Get list of strings. """
        v = self._get(key, List[str], default)
        return [ str(e) for e in v ]

    def float(self, key: str, default: Optional[float] = None) -> float:
        return self.get(key, float, default)

    def int(self, key: str, default: Optional[int] = None) -> int:
        return self.get(key, int, default)

    def bool(self, key: str, default: Optional[bool] = None) -> bool:
        return self.get(key, bool, default)

    #this function must be last, otherwise mypy is confused
    def str(self, key: str, default: Optional[str] = None) -> str:
        return self.get(key, str, default)

# }}}

class Records: # {{{
    def __init__(self, rc: "RecordController", results: Dict[str, bool]) -> None:
        self.type      = rc.type
        self.name      = rc.name
        self.ttl       = rc.ttl
        self.timestamp = int(time.time())
        self.results   = results
# }}}

DNSResult = Tuple[str, List[str]]

class RecordController: # {{{
    """ This is in fact launcher of checks for one "loadbalanced" record.
        It periodically runs checks and submits results to trio channel
        specified in run() method.

        logger argument is in fact mandatory, if you do not want just parse configuration
    """

    results: Dict[str, bool]
    type:    str
    name:    str
    proto:   int
    family:  socket.AddressFamily

    def __init__(self, name: str, type: str, config: ConfigExtractor, logger: Optional["Logger"]): # {{{
        with config:
            self.name   = name
            self.type   = type
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

            self.ttl         = config.int('ttl')
            self.dest        = config.l_str('dest')
            self.interval    = config.float('interval')
            self.shift       = config.float('shift')
            self.check       = config.l_str('check')
            self.timeout     = config.float('timeout')
            self.dns_timeout = config.float('dns_timeout')
            self.regex       = re.compile(config.str('expect'))
            self.fallback    = config.str('fallback', '')

        if logger is not None:
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
    # Some typed cursor magic
    C_id         = TypedDict('C_id',         {"id": int})
    C_id_content = TypedDict('C_id_content', {"id": int,   "content": str})
    C_name_type  = TypedDict('C_name_type',  {"name": str, "type": str})

class SqlController: # {{{
    domain_id: int

    def __init__(self, config: ConfigExtractor, sql_cfg: ConfigExtractor, logger: "Logger") -> None: # {{{
        self.logger = logger

        with config:
            self.delete_unknowns  = config.bool('delete_unknowns')
            self.domain_name      = config.str('domain_name')
            loglevel              = config.str('loglevel')
            logger.set_loglevel(loglevel)
        self.domain_name = '.' + self.domain_name.lstrip('.')

        sqlcfg:Dict[str,object] = dict(cursorclass=trio_mysql.cursors.DictCursor)
        sqlcfg.update(sql_cfg._config)
        try:
            self.conn                 = trio_mysql.connect(**sqlcfg)
        except Exception as e:
            raise ConfigError("Error configuring connection to mysql: %s" % (e,))
    # }}}

    async def exl(self, cursor: trio_mysql.cursors.Cursor, query: str, arg: Optional[object]=None) -> None: # {{{
        """ Log and execute query. Internal function. """
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

    async def prepare(self) -> None: # {{{
        """ Asynchronous part of init """
        await self.conn.connect()
        async with self.conn.cursor() as cursor: # type: trio_mysql.TCursor[C_id]
            await self.exl(cursor, "SELECT id FROM domains WHERE name = %s", (self.domain_name[1:],))
            row = await cursor.fetchone()
            self.domain_id = row['id']
    # }}}

    async def delete_unkown_entries(self, known_set: Set[Tuple[str, str]]) -> None: # {{{
        """ Deletes all entries that are not in known_set. """
        assert self.domain_name.startswith('.')
        unknown_set = set()
        self.logger.debug("sql", "Examining database for records not in %r" % (known_set,))
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
        """ Insert results of RecordController into database. """
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
    """ Just a simple stderr colorised logger. It may be replaced by something more
        sofisticated in future. """

    class LogLevel(enum.IntEnum):
        DEBUG   = 0
        INFO    = 1
        WARNING = 2
        ERROR   = 3

    min_level: LogLevel = LogLevel.DEBUG

    def set_loglevel(self, loglevel: str) -> None:
        self.min_level = self.LogLevel[loglevel.upper()]

    def debug(self, module: str, msg:str) -> None:
        self.msg(self.LogLevel.DEBUG, module, msg)

    def info(self, module: str, msg:str) -> None:
        self.msg(self.LogLevel.INFO, module, msg)

    def warning(self, module: str, msg:str) -> None:
        self.msg(self.LogLevel.WARNING, module, msg)

    def error(self, module: str, msg:str) -> None:
        self.msg(self.LogLevel.ERROR, module, msg)

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

    def msg(self, level: LogLevel, module: str, msg: str) -> None:
        if self.min_level <= level:
            sys.stderr.write('%s[%s]%s %s[%s]%s %s\n' % (
                self.COLORS[level], self.NAMES[level], self.COL_R,
                self.COL_M, module, self.COL_R,
                msg) )
# }}}

class Main: # {{{
    """ And now, put it all together, mix, stir, boil for 15 minutes, ... """

    def __init__(self) -> None: # {{{
        parser = argparse.ArgumentParser(description="DNSLB Controller")
        parser.add_argument('-l', '--loglevel', default=None,
            choices = [ x.name.lower() for x in Logger.LogLevel ],
            help    = "Log level, messages with lower severity will not be printed.")

        if os.environ.get('USER','') == 'dnslb' or os.getuid() == 0:
            default_cfg_path = '/etc/dnslb/dnslb.toml'
        else:
            default_cfg_path = os.path.join(os.path.dirname(__file__),'configs/dnslb/dnslb.toml')
        parser.add_argument('-c', '--config', default=default_cfg_path, help='Configuration file')

        options = parser.parse_args()

        self.logger = Logger()

        #FIXME parse command line (config file, debug level)
        try:
            with ConfigExtractor(toml.load(options.config)) as config: # type: ignore
                conf_global  = config.section('global')
                conf_sql     = config.section('mysql')
                conf_records = config.section('records')
                conf_default = config.section('default', default=True)

            try:
                RecordController('default', 'A', conf_default, None)
            except MissingConfigError:
                pass

            # sets also loglevel, we parse conf_global in SqlController
            self.sql = SqlController(conf_global, conf_sql, self.logger)

            if options.loglevel is not None: # type: ignore
                loglevel:str = options.loglevel
                self.logger.set_loglevel(loglevel)

            self.rcs = []
            for name in conf_records:
                r = conf_records.section(name, quote_name = True)
                for t in ('A', 'AAAA'):
                    if t in r:
                        self.rcs.append(RecordController(name, t, r.section(t, default = conf_default), self.logger))
        except ConfigError as e:
            sys.stderr.write(str(e) + '\n')
            sys.exit(126)
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
    await m.main()

trio.run(main)

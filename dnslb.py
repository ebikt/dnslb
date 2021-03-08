#!/usr/bin/python3

import argparse
import os
import re
import signal
import socket
import sys
import time
import toml
import traceback

from typing import AsyncIterator, Dict, List, Optional, Set, Tuple

sys.path.insert(0, os.path.dirname(__file__) + '/lib')

import trio
import trio_mysql
import trio_mysql.cursors

from dnslb.config_extractor import ConfigExtractor, ConfigError
from dnslb.simple_logger    import Logger
from dnslb.systemd_notifier import SDNotifier

MYPY=False
if MYPY:
    from typing_extensions import TypedDict

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

    results: Dict[str, int]
    type:    str
    name:    str
    proto:   int
    family:  socket.AddressFamily
    prio_regex:    Optional[re.Pattern[str]]
    prio_min_cnt: int

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
            prio_regex       = re.compile(config.str('prio_regex', ''))
            if prio_regex.groups > 0:
                self.prio_regex = prio_regex
            else:
                self.prio_regex = None
            self.prio_min_cnt = config.int('prio_min_cnt', 1)
            self.fallback     = config.str('fallback', '')

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
            outu = result.stdout.decode('utf-8', 'ignore')
            if self.regex.search(outu):
                if self.prio_regex is not None:
                    m = self.prio_regex.search(outu)
                    if m:
                        prio = int(m.group(1))
                        self.logger.debug(logprefix, "destination OK with priority %d" % (prio,))
                    else:
                        prio = 1
                        self.logger.debug(logprefix, "destination OK, priority not matched (using 1)")
                    self.results[address] = prio
                else:
                    self.logger.debug(logprefix, "destination OK")
                    self.results[address] = 1
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
                        self.results[address] = 0
                        nursery.start_soon(self.run_check, address)
                    else:
                        self.logger.debug(self.logprefix, " %s -> %s, Ignoring duplicit result." % (query, address))
    # }}}

    async def run_one(self, sqlqueue, limiter): # type: (trio.MemorySendChannel[Records], trio.CapacityLimiter) -> None # {{{
        async with limiter:
            try:
                qin:  trio.MemorySendChannel[DNSResult]
                qout: trio.MemoryReceiveChannel[DNSResult]
                qin, qout = trio.open_memory_channel(len(self.dest))
                async with trio.open_nursery() as nursery:
                    nursery.start_soon(self.resolve_all, qin)
                    nursery.start_soon(self.process_resolved, qout, nursery)

                any_ok = False
                for rv in self.results.values():
                    if rv > 0: any_ok = True

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
                            self.results[r] = 1
                    else:
                        self.logger.warning(self.logprefix, "All checks failed, no fallback provided, deleting entry.")
                self.logger.debug(self.logprefix, "Sending result")
                if len(self.results):
                    histo:Dict[int, int] = {}
                    for v in self.results.values():
                        if v >= 0:
                            if v not in histo:
                                histo[v] = 0
                            histo[v] += 1
                    sumc = 0
                    for v, c in sorted(histo.items(), reverse=True):
                        sumc = sumc + c
                        minv = v
                        if sumc >= self.prio_min_cnt:
                            break
                else:
                    minv = 1
                await sqlqueue.send(Records(self, { k:v >= minv for k, v in self.results.items()}))
                self.results = None # type: ignore # Disable editting of self.results after passed away
            except trio.Cancelled:
                raise
            except Exception:
                self.logger.error(self.logprefix, "Error occured %s" % (traceback.format_exc(),))
                pass
    # }}}

    async def run_loop(self, sqlqueue, limiter): # type: (trio.MemorySendChannel[Records], trio.CapacityLimiter) -> None # {{{
        while True:
            sleep = self.interval - (time.time() - self.shift) % self.interval
            self.logger.debug(self.logprefix, "waiting %.2f seconds" % (sleep,))
            await trio.sleep(sleep)
            await self.run_one(sqlqueue, limiter)
    # }}}
# }}}

if MYPY:
    # Some typed cursor magic
    C_id         = TypedDict('C_id',         {"id": int})
    C_id_c_d     = TypedDict('C_id_c_d',     {"id": int,   "content": str,  "disabled": int})
    C_name_type  = TypedDict('C_name_type',  {"name": str, "type":    str})

class SqlController:# {{{
    domain_id: int

    def __init__(self, zone: str, delete_unknowns: bool, sql_cfg: ConfigExtractor, logger: "Logger") -> None: # {{{
        self.logger = logger
        self.delete_unknowns = delete_unknowns
        self.domain_name = '.' + zone.lstrip('.')
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
        else:
            self.logger.debug("sql", "  Returned 0 rows")
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
                            await self.exl(cursor, "DELETE FROM records WHERE name = %s AND type = %s AND domain_id = %s", unk)
                    else:
                        self.logger.warning("sql", "Keeping unknown entries: %r" % (unknown_set))
    # }}}

    async def update_records(self, records: Records) -> None: # {{{
        """ Insert results of RecordController into database. """
        assert self.domain_name.startswith('.')
        name = records.name + self.domain_name
        now = int(records.timestamp)
        async with self.conn.transaction():
            async with self.conn.cursor() as cursor: # type: trio_mysql.TCursor[C_id_c_d]
                content_ids:Dict[str, Tuple[int, int]] = {}
                delete_ids:Dict[int, Tuple[str, bool]] = {}
                await self.exl(cursor, "SELECT id, content, disabled FROM records WHERE name = %s AND type = %s AND domain_id = %s",
                    (name, records.type, self.domain_id))
                for row in cursor:
                    content = str(row['content'])
                    id = int(row['id'])
                    if content not in records.results:
                        delete_ids[id] = (content, False if int(row['disabled']) else True)
                    else:
                        content_ids[content] = (id, int(row['disabled']))
                for content, enabled in records.results.items():
                    disabled = 0 if enabled else 1
                    if content in content_ids:
                        id, last_disabled = content_ids[content]
                        if disabled != last_disabled:
                            self.logger.info("sql", "Record %s %s -> %s changed state to %s" % (name, records.type, content, "disabled" if disabled else "enabled"))
                        await self.exl(cursor, "UPDATE records SET disabled = %s, last_lb_check = %s, ttl = %s WHERE id = %s",
                                (disabled, now, records.ttl, id))
                    else:
                        self.logger.info("sql", "Record %s %s -> %s adding new record with state %s" % (name, records.type, content, "disabled" if disabled else "enabled"))
                        await self.exl(cursor, "INSERT INTO records(domain_id, name, type, content, ttl, disabled, last_lb_check)" +
                            " VALUES (%s, %s, %s, %s, %s, %s, %s)",
                            (self.domain_id, name, records.type, content, records.ttl, disabled, now))
                if len(delete_ids):
                    self.logger.info('sql', 'Deleting old or fallback entries of %s %s: %r' % (name, records.type, delete_ids))
                    await self.exl(cursor, "DELETE FROM records WHERE id IN (" + ",".join(str(i) for i in delete_ids) + ")")
    # }}}
# }}}

class Main: # {{{
    """ And now, put it all together, mix, stir, boil for 15 minutes, ... """

    def __init__(self, immediate_checks: bool, sd_notifier: SDNotifier, logger:Logger) -> None: # {{{
        self.immediate_checks = immediate_checks
        self.sd_notifier      = sd_notifier
        self.logger           = logger
        parser = argparse.ArgumentParser(description="DNSLB Controller")
        parser.add_argument('-l', '--loglevel', default=None,
            choices = [ x.name.lower() for x in Logger.LogLevel ],
            help    = "Log level, messages with lower severity will not be printed.")

        if os.environ.get('USER','') == 'dnslb' or os.getuid() == 0:
            default_cfg_path = '/etc/dnslb/dnslb.toml'
        else:
            default_cfg_path = os.path.join(os.path.dirname(__file__),'configs/dnslb/dnslb.toml')
        parser.add_argument('-c', '--config', default=default_cfg_path, help='Configuration file')
        parser.add_argument('-t', '--check-config', default=False, action='store_true', help='check configuration file and exit')

        options = parser.parse_args()

        #FIXME parse command line (config file, debug level)
        try:
            with ConfigExtractor(toml.load(options.config)) as config: # type: ignore
                conf_global  = config.section('global')
                conf_sql     = config.section('mysql')
                conf_records = config.section('records')
                conf_default = config.section('default', default=True)

            RecordController('default', 'A', conf_default, None)

            with conf_global:
                sql_del_unk = conf_global.bool('delete_unknowns')
                sql_zone    = conf_global.str('domain_name')
                loglevel    = conf_global.str('loglevel')
                self.rclim  = trio.CapacityLimiter(conf_global.int('max_record_checks'))

            if options.loglevel is not None: # type: ignore
                loglevel = options.loglevel

            self.logger.set_loglevel(loglevel)

            self.sql = SqlController(sql_zone, sql_del_unk, conf_sql, self.logger)

            self.rcs = []
            for name in conf_records:
                r = conf_records.section(name, quote_name = True)
                for t in ('A', 'AAAA'):
                    if t in r:
                        self.rcs.append(RecordController(name, t, r.section(t, default = conf_default), self.logger))
        except ConfigError as e:
            sys.stderr.write(str(e) + '\n')
            sys.exit(126)

        if options.check_config: #type: ignore
            self.check_config = True
        else:
            self.check_config = False
    # }}}

    async def run_record_controllers(self, queue): # type: (trio.MemorySendChannel[Records]) -> None # {{{
        async with queue:
            if self.immediate_checks:
                async with trio.open_nursery() as nursery_first:
                    for rc in self.rcs:
                        nursery_first.start_soon(rc.run_one, queue, self.rclim)
                self.logger.info('main', 'First check done for all queries, now it is safe to start dns server')
                await self.sd_notifier.notify('Running', ready=True)
            else:
                await self.sd_notifier.notify('Reloaded', ready=True)
            async with trio.open_nursery() as nursery:
                for rc in self.rcs:
                    nursery.start_soon(rc.run_loop, queue, self.rclim)
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

    async def handle_reload(self, sigiter: AsyncIterator[signal.Signals], canceler: trio.CancelScope) -> None:
        async for signum in sigiter:
            if signum == signal.SIGUSR1:
                self.logger.info('main', 'Reloading')
                await self.sd_notifier.notify("Reloading", reloading=True)
                try:
                    new_main = Main(False, self.sd_notifier, self.logger)
                    await new_main.initialize()
                except Exception as e:
                    self.logger.error('main', 'Error loading new configuration: %s' % (e,))
                    await self.sd_notifier.notify("Reload failed!", ready=True)
                    continue
                self.next_main = new_main
                canceler.cancel()
                return

    next_main: Optional["Main"]

    async def initialize(self) -> bool: # {{{
        self.next_main = None
        await self.sql.prepare()
        max_interval = 0.0
        for rc in self.rcs:
            max_interval = max(max_interval, rc.interval)
        if self.immediate_checks:
            await self.sd_notifier.notify(extend_timeout = max_interval)
        return not self.check_config
    # }}}

    async def main(self, usr1: AsyncIterator[signal.Signals]) -> Optional["Main"]: # {{{
        await self.sql.delete_unkown_entries(set([(rc.name, rc.type) for rc in self.rcs]))
        sqlin:  trio.MemorySendChannel[Records]
        sqlout: trio.MemoryReceiveChannel[Records]
        sqlin, sqlout = trio.open_memory_channel(len(self.rcs))
        self.logger.debug("main", "Start loops.")
        async with trio.open_nursery() as nursery:
            nursery.start_soon(self.run_record_controllers, sqlin)
            nursery.start_soon(self.run_sql, sqlout)
            nursery.start_soon(self.handle_reload, usr1, nursery.cancel_scope)
        if self.next_main:
            self.logger.info('main', 'Reloaded.')
        else:
            self.logger.debug("main", "Finish.")
        return self.next_main
    # }}}
# }}}

async def main() -> None:
    logger = Logger()
    sd_notifier = SDNotifier(logger = logger)
    with trio.open_signal_receiver(signal.SIGUSR1) as usr1:
        m: Optional[Main] = Main(True, sd_notifier, logger)
        await sd_notifier.notify(status="Starting.")
        if m is not None:
            if not await m.initialize():
                return
        while m is not None:
            m = await m.main(usr1)

trio.run(main)

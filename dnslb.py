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
import glob

from typing import AsyncIterator, Dict, List, Optional, Set, Tuple, cast, Union

sys.path.insert(0, (os.path.dirname(__file__) or '.') + '/lib')

import trio
import trio_mysql
import trio_mysql.cursors

from dnslb.config_extractor import ConfigExtractor, ConfigError, MissingConfigError
from dnslb.simple_logger    import Logger
from dnslb.systemd_notifier import SDNotifier

# {{{ Typing tweaks
MYPY=False
if MYPY:
    from typing_extensions import TypedDict
    ReStr = re.Pattern[str]
else:
    try:
        # Python 3.9+
        ReStr = re.Pattern[str]
    except TypeError:
        ReStr = re.Pattern
        # Python 3.7-
# }}}

class HealthCheckResult: # {{{
    """ Result of single health check. """
    retcode:  int
    priority: Optional[int]

    NOT_MATCHED = -1
    TIMED_OUT   = -2

    def __init__(self, retcode: int, priority: Optional[int] = None):
        self.retcode  = retcode
        self.priority = priority
# }}}

class HealthCheckRecord: # {{{
    """ Result of single health check after calculation of priority threshold
        and comparing priority to the threshold.
        (`enabled` contains result of that comparsion) """
    enabled:  bool
    retcode:  int
    priority: Optional[int]
    def __init__(self, result: Union[HealthCheckResult, "HealthCheckRecord"], enabled: bool):
        # We also accept HealthCheckRecord in initialiser, for the special case when fallback
        # hostname is same as one of the balanced hostnames. We need to override value
        # of the enabled flag then.
        self.retcode  = result.retcode
        self.priority = result.priority
        self.enabled  = enabled
# }}}

class Records: # {{{
    """ Records for one loadbalanced address as they will be stored into DNS database. """
    def __init__(self, rc: "RecordController", results: Dict[str, HealthCheckRecord]) -> None:
        self.type      = rc.type
        self.name      = rc.name
        self.ttl       = rc.ttl
        self.timestamp = int(time.time())
        self.results   = results
# }}}

class Dest: # {{{
    """ Parsing of destination string from configuration. """
    name:str
    prio = 1
    cache_value:List[str]
    cache_time = 0.0
    def __init__(self, dest_str: str) -> None:
        """ currently only `domain` or `domain@priority` supported """
        p = dest_str.split('@',1)
        self.name = p[0]
        if len(p) > 1:
            try:
                self.prio = int(p[1])
            except Exception:
                raise ConfigError("priority after '@' must be integer, got {}".format(repr(dest_str)))
# }}}

""" What do Dest resolve to in DNS. """
DestIPs = Tuple[Dest, List[str]]

class ResolvingContext: # {{{
    if MYPY:
        qsend: trio.MemorySendChannel[DestIPs]
        qrecv: trio.MemoryReceiveChannel[DestIPs]
    def __init__(self, queue_len, nursery): # type: (int, trio.Nursery) -> None
        self.t_start = time.time()
        self.t_resolved = -1.0
        self.qsend, self.qrecv = trio.open_memory_channel(queue_len)
        self.expected_resolves:Set[str] = set()
        self.nursery = nursery
# }}}

class RecordController: # {{{
    """ This is in fact launcher of checks for one "loadbalanced" entry.
        It periodically runs checks and submits results to trio channel
        specified in run() method.

        logger argument is in fact mandatory, if you do not want just parse configuration
    """

    Id = Tuple[str, int]

    results: Dict[str, HealthCheckResult]
    type:    str
    name:    str
    proto:   int
    family:  socket.AddressFamily
    prio_regex:    Optional[ReStr]
    prio_min_cnt: int
    dest:    Dict[str, Dest]

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
                self.socktype:int = getattr(socket.SocketKind, config.str('socktype'))
            else:
                self.socktype = {
                    socket.IPPROTO_TCP: socket.SOCK_STREAM,
                    socket.IPPROTO_UDP: socket.SOCK_DGRAM,
                }.get(self.proto, 0)

            self.ttl         = config.int('ttl')
            self.dest = {}
            for ds in config.l_str('dest'):
                d = Dest(ds)
                if d.name in self.dest and d.prio != self.dest[d.name].prio:
                    raise ConfigError(f"Destination {d.name} occurs multiple times for {self.name} with different priorities.")
                else:
                    self.dest[d.name] = d
            self.interval    = config.float('interval')
            self.shift       = config.float('shift')
            self.check       = config.l_str('check')
            self.timeout     = config.float('timeout')
            self.dns_timeout = config.float('dns_timeout')
            self.regex       = re.compile(config.str('expect'))
            prio_regex       = re.compile(config.str('prio_regex', ''))
            self.dns_ttl     = config.float('dns_ttl', 300) #FIXME use global value
            if prio_regex.groups > 0:
                self.prio_regex = prio_regex
            else:
                self.prio_regex = None
            self.prio_min_cnt = config.int('prio_min_cnt', 1)
            fallback     = config.str('fallback', '')
            if fallback:
                if '@' in fallback:
                    raise ConfigError(f"fallback entry priority is not supported")
                self.fallback:Optional[Dest] = Dest(fallback)
            else:
                self.fallback = None

        if logger is not None:
            self.logger = logger
            logprefix = self.logprefix = "%s,%s" % (self.name, self.type)
            logger.info(logprefix, "dest: " + ', '.join(f"{d.name}@{d.prio}" for _,d in sorted(self.dest.items())))
            logger.info(logprefix, "at time %% %.2f == %.2f" % (self.interval, self.shift))
            logger.info(logprefix, "check command: %r" % (self.check,))
            logger.info(logprefix, "check timeout: %.2f, dns timeout: %.2f, check.regex:%r" %
                (self.timeout, self.dns_timeout, config.str('expect')))

        dns_ttl_cycles = self.dns_ttl / self.interval
        if abs(round(dns_ttl_cycles) - dns_ttl_cycles) < 0.01:
            # dns_ttl is multiple of interval, this may cause
            # nondeterministic behaviour, so we offset it a little
            self.dns_ttl += 0.05 * self.interval
    # }}}

    def id(self) -> "RecordController.Id":
        return (self.name, self.proto)

    async def run_check(self, query: Dest, address: str) -> None: # {{{
        """ Do a health check of single destination address `address`
            (including parsing output) and store result in `self.results`. """

        fmt = { "address": address}
        cmdline = [ x % fmt for x in self.check ]
        logprefix = "%s,%s" % (self.logprefix, address)
        try:
            self.logger.debug(logprefix, "launching %r" % (cmdline,))
            with trio.fail_after(self.timeout):
                result = await trio.run_process(cmdline, capture_stdout=True)
            outu = result.stdout.decode('utf-8', 'ignore')
            #FIXME: propagate some (sort of) error string? E.g. to prometheus/victoriadb?
            if result.returncode != 0:
                self.logger.debug(logprefix, "destination failed rc:%d" % (result.returncode,));
                self.results[address] = HealthCheckResult( result.returncode )
            elif self.regex.search(outu):
                if self.prio_regex is not None:
                    m = self.prio_regex.search(outu)
                    if m and cast(str, m.group(1)) == '@':
                        self.logger.debug(logprefix, "destination OK, setting priority %d (captured @)" % (query.prio,))
                        self.results[address] = HealthCheckResult( result.returncode, query.prio)
                        prio = query.prio
                    elif m:
                        try:
                            prio = int(cast(str, m.group(1)))
                        except ValueError:
                            prio = len(cast(str,m.group(1)))+1
                        self.logger.debug(logprefix, "destination OK with priority %d" % (prio,))
                    else:
                        prio = -1
                        self.logger.debug(logprefix, "destination OK, priority not matched (disabling by prio: -1)")
                    self.results[address] = HealthCheckResult( result.returncode, prio)
                else:
                    self.logger.debug(logprefix, "destination OK, setting priority %d" % (query.prio,))
                    self.results[address] = HealthCheckResult( result.returncode, query.prio)
            else:
                self.logger.debug(logprefix, "destination failed: regex not matched")
                self.results[address] = HealthCheckResult( HealthCheckResult.NOT_MATCHED )
        except Exception as e:
            self.logger.warning(logprefix, "check error: %s" % (e,))
            pass
    # }}}

    async def resolve_one(self, ctx, dest): # type: (ResolvingContext, Dest) -> None # {{{
        """ Resolve single destination name to one or more ip addresses,
            send result into queue."""

        logprefix = "%s:%s" % (self.logprefix, dest)
        self.logger.debug(logprefix, "issuing getaddrinfo()")
        try:
            aresult = await trio.socket.getaddrinfo(dest.name, 0, self.family, self.socktype, self.proto, 0)
            result = [ r[4][0] for r in aresult ]
            self.logger.debug(logprefix, "getaddrinfo (%s) returned %d results" % (dest.name, len(result)))
        except trio.Cancelled as e:
            self.logger.warning(logprefix, "getaddrinfo (%s) cancelled: %s" % (dest.name, e))
            raise
        except socket.gaierror as e:
            if e.errno in (socket.EAI_NODATA,):
                self.logger.warning(logprefix, "getaddrinfo (%s) \"failed\": %s - using empty result" % (dest.name, e))
                result = []
            else:
                self.logger.warning(logprefix, "getaddrinfo (%s) failed: %s" % (dest.name, e))
                return
        except Exception as e:
            self.logger.error(logprefix, "getaddrinfo (%s) failed: %s" % (dest.name, e))
            return

        dest.cache_value = result
        dest.cache_time  = ctx.t_start
        await ctx.qsend.send( (dest, result) )
    # }}}

    async def resolve_all(self, ctx): # type: (ResolvingContext) -> None # {{{
        """ Resolve all destination addresses in parallel
            with abort after timeout.
            Send results into `queue` as soon as they are available. """

        async with ctx.qsend:
            self.logger.debug(self.logprefix, "starting to resolve entries (timeout: %.2f)" % (self.dns_timeout,))
            with trio.move_on_after(self.dns_timeout):
                try:
                    async with trio.open_nursery() as nursery:
                        for n, dest in self.dest.items():
                            assert n == dest.name
                            self.logger.debug(self.logprefix, "start soon: resolve %r" % (dest,))
                            ctx.expected_resolves.add(n)
                            nursery.start_soon(self.resolve_one, ctx, dest)
                except Exception as e:
                    self.logger.debug(self.logprefix, "exc %s" % (e,))
                    raise
            self.logger.debug(self.logprefix, "finished resolving entries")
            for n in list(ctx.expected_resolves):
                dest = self.dest[n]
                if ctx.t_start - dest.cache_time < self.dns_ttl:
                    await ctx.qsend.send( (dest, dest.cache_value) )
            ctx.t_resolved = time.time()
    # }}}

    async def process_resolved(self, ctx): # type: (ResolvingContext) -> None # {{{
        """ Run health check on resolved destination addresses in parallel,
            as soon as they pop up in `queue`.
            Results of the healh checks are stored in `self.results`. """
        self.results = {}
        async with ctx.qrecv:
            async for query, result in ctx.qrecv:
                try:
                    ctx.expected_resolves.remove(query.name)
                except KeyError:
                    continue
                if ctx.t_start > query.cache_time:
                    self.logger.info(self.logprefix, "Using cached dns entries for %s: %r (age %.2f)" %
                        (query.name, query.cache_value, ctx.t_start - query.cache_time))
                for address in result:
                    if address not in self.results:
                        self.logger.debug(self.logprefix, " %s -> %s, Queueing check." % (query, address))
                        self.results[address] = HealthCheckResult(HealthCheckResult.TIMED_OUT)
                        ctx.nursery.start_soon(self.run_check, query, address)
                    else:
                        self.logger.debug(self.logprefix, " %s -> %s, Ignoring duplicit result." % (query, address))
    # }}}

    async def run_one(self, sqlqueue, limiter): # type: (trio.MemorySendChannel[Records], trio.CapacityLimiter) -> None # {{{
        """ Single iteration of health-checking all destination records
            for one loadbalanced entry.
            Resolves all destination entries and runs health checks
            on them. Then it calculates priority thresholds and decides
            which destination entries will be visible in DNS.
            Send Records (result of this computation) to sqlchannel.

            Note: Parallel run of more instances of this method on single
                  instance of RecordController is not supported. """
        async with limiter:
            try:
                async with trio.open_nursery() as nursery:
                    ctx = ResolvingContext(len(self.dest), nursery)
                    # Start resolver (it writes results to qsend)
                    nursery.start_soon(self.resolve_all, ctx)
                    # Start healthchecks as soon as they are available (in qrecv)
                    nursery.start_soon(self.process_resolved, ctx)
                    # Wait for all async stuff in this block to finish.
                if ctx.t_resolved <= 0: ctx.t_resolved = time.time()
                if len(ctx.expected_resolves):
                    self.logger.warning(self.logprefix, "Resolved only {resolved} of {total} entries in {time:.3g} seconds.".format(
                        total = len(self.dest),
                        resolved = len(self.dest) - len(ctx.expected_resolves),
                        time = ctx.t_resolved - ctx.t_start
                    ))
                    delete = False
                    deleting = " No update (resolve failure)."
                else:
                    delete = True
                    deleting = " Deleting entry."

                any_ok = False
                for rv in self.results.values():
                    if rv.priority and rv.priority > 0: any_ok = True

                records:Dict[str,HealthCheckRecord]
                if not any_ok:
                    # No destination record did pass the healthcheck, process fallback destination record.
                    # Note that we do not have explicit timeout for dns resolving fallback record.

                    records = { k:HealthCheckRecord(v, False) for k, v in self.results.items() }
                    fallback = self.fallback
                    if fallback is not None:
                        if fallback.name in self.dest:
                            dest = self.dest[fallback.name]
                        else:
                            dest = fallback
                        assert dest.name == fallback.name
                        self.logger.warning(self.logprefix, "All checks failed, resolving fallback.")
                        if ctx.t_start - dest.cache_time < min(self.interval, self.dns_ttl) and len(dest.cache_value):
                            result = dest.cache_value
                        else:
                            result = []
                            with trio.move_on_after(self.dns_timeout):
                                t1 = time.time()
                                try:
                                    aresult = await trio.socket.getaddrinfo(dest.name, 0, self.family, self.socktype, self.proto, 0)
                                    result = [ r[4][0] for r in aresult ]

                                    dest.cache_value = result
                                    dest.cache_time  = t1
                                except socket.gaierror as e: # Cache NXDOMAIN
                                    if e.errno in (socket.EAI_NODATA,):
                                        dest.cache_value = []
                                        dest.cache_time = t1
                                    self.logger.warning(self.logprefix, "fallback getaddrinfo failed: %s" % (e,))
                                except Exception as e:
                                    self.logger.warning(self.logprefix, "fallback getaddrinfo failed: %s" % (e,))
                        if len(result) == 0:
                            if ctx.t_start - dest.cache_time < self.dns_ttl and len(dest.cache_value) > 0:
                                self.logger.warning(self.logprefix, "Cannot resolve fallback, using cached value")
                            else:
                                self.logger.warning(self.logprefix, "Cannot resolve fallback." + deleting)
                        for r in result:
                            self.logger.debug(self.logprefix, "Adding fallback entry %s" % (r,))
                            records[r] = HealthCheckRecord(records.get(r, HealthCheckResult(0, None)), True)
                    else:
                        self.logger.warning(self.logprefix, "All checks failed, no fallback provided." + deleting)
                else:
                    # Some destination records passed the healthcheck. Calculate priority threshold
                    # and use it for converting HealthCheckResults to HealthCheckRecords.

                    histo:Dict[int, int] = {}
                    for v in self.results.values():
                        if v.priority and v.priority > 0:
                            if v.priority not in histo:
                                histo[v.priority] = 0
                            histo[v.priority] += 1
                    sumc = 0
                    for vi, c in sorted(histo.items(), reverse=True):
                        sumc = sumc + c
                        minv = vi
                        if sumc >= self.prio_min_cnt:
                            break
                    if minv > 1: minv -= 1
                    else: minv = 0
                    records = { k:HealthCheckRecord(v, False if v.priority is None else v.priority > minv)
                                for k, v in self.results.items() }

                if len(records) or delete:
                    self.logger.debug(self.logprefix, "Sending result")
                    await sqlqueue.send(Records(self, records))
                else:
                    self.logger.error(self.logprefix, "Not updating due to resolve failure(s).")
                self.results = None # type: ignore # Disable editting of self.results after passed away
            except trio.Cancelled:
                raise
            except Exception:
                self.logger.error(self.logprefix, "Error occured %s" % (traceback.format_exc(),))
                pass
    # }}}

    async def run_loop(self, sqlqueue, limiter): # type: (trio.MemorySendChannel[Records], trio.CapacityLimiter) -> None # {{{
        """ Run iteration `run_one()` at configured times.
            (when (time.time() - self.shift) % self.interval == 0). """
        while True:
            sleep = self.interval - (time.time() - self.shift) % self.interval
            self.logger.debug(self.logprefix, "waiting %.2f seconds" % (sleep,))
            await trio.sleep(sleep)
            await self.run_one(sqlqueue, limiter)
    # }}}
# }}}

if MYPY: # {{{ Some typed SQL cursor magic
    C_id         = TypedDict('C_id',         {"id": int})
    C_id_c_d     = TypedDict('C_id_c_d',     {"id": int,   "content": str,  "disabled": int})
    C_name_type  = TypedDict('C_name_type',  {"name": str, "type":    str})
# }}}

def nameFromAscii(s: Union[str, bytes, int], strict:bool = True) -> str: # {{{
    """ Convert ascii string/sequence of bytes to string. Raise
        assertion if other input(int) is provided.
        We need this to cope with untyped output of SQL queries. """
    if isinstance(s, str):
        return s
    elif isinstance(s, bytes):
        return s.decode('ascii')
    elif strict:
        raise AssertionError("Invalid type of name: %s (%r) " % (type(s), s))
    return str(s)
# }}}

class SqlController:# {{{
    """ Object that handles communication with SQL database with
        records for PowerDNS for configured DNSLB domain. """

    domain_id: int

    def __init__(self, zone: str, delete_unknowns: bool, sql_cfg: ConfigExtractor, logger: "Logger") -> None: # {{{
        """ Early initialization. See prepare() for asynchronous part. """

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

    async def delete_unknown_entries(self, known_set: Set[Tuple[str, str]]) -> None: # {{{
        """ Deletes all entries that are not in known_set. """

        assert self.domain_name.startswith('.')
        unknown_set = set()
        self.logger.debug("sql", "Examining database for records not in %r" % (known_set,))
        async with self.conn.transaction():
            async with self.conn.cursor() as cursor: # type: trio_mysql.TCursor[C_name_type]
                await self.exl(cursor, "SELECT r.name, r.type FROM records r WHERE domain_id = %s AND type in ('A', 'AAAA')", (self.domain_id,))
                async for row in cursor: #this cursor is prefetched (buffered), no need to async
                    name  = nameFromAscii(row['name'])
                    type_ = nameFromAscii(row['type'])
                    if name.endswith(self.domain_name):
                        entry = (name[:-len(self.domain_name)], type_)
                        if entry not in known_set:
                            unknown_set.add( (name, type_, self.domain_id) )
                if len(unknown_set):
                    if self.delete_unknowns:
                        self.logger.warning("sql", "Deleting unknown entries: %r" % (unknown_set))
                        for unk in unknown_set:
                            await self.exl(cursor, "DELETE FROM records WHERE name = %s AND type = %s AND domain_id = %s", unk)
                    else:
                        self.logger.warning("sql", "Keeping unknown entries: %r" % (unknown_set))
    # }}}

    async def update_records(self, records: Records) -> None: # {{{
        """ Insert results of RecordController into database.
            Note that we do not use transactions here as we expect
            only single isinstance of dnslb software to be modifying
            data in the database. Moreover DNS itself is not atomic,
            thus we do not try to prevent DNS from seeing mixed result
            of old and new data. We do insert/update before delete,
            so that there is a chance to always return some adresses.
            TTL should be set to some small value (1s) to prevent caches
            from keeping inconsistent data too long. """

        assert self.domain_name.startswith('.')
        name = records.name + self.domain_name
        now = int(records.timestamp)
        async with self.conn.transaction():
            async with self.conn.cursor() as cursor: # type: trio_mysql.TCursor[C_id_c_d]
                content_ids:Dict[str, Tuple[int, int]] = {} # ip -> id, last_disabled
                delete_ids:Dict[int, Tuple[str, bool]] = {} # id -> ip, disabled
                await self.exl(cursor, "SELECT id, content, disabled, last_lb_check_result FROM records WHERE name = %s AND type = %s AND domain_id = %s",
                    (name, records.type, self.domain_id))
                async for row in cursor:
                    content = nameFromAscii(row['content'], False)
                    #self.logger.debug("TRACE", "%r (==str(%r)) in %r" % (content, row['content'], records.results))
                    id = int(row['id'])
                    if content not in records.results:
                        delete_ids[id] = (content, False if int(row['disabled']) else True)
                    else:
                        content_ids[content] = (id, int(row['disabled']))
                for content, en_res in records.results.items():
                    disabled = 0 if en_res.enabled else 1
                    if content in content_ids:
                        id, last_disabled = content_ids[content]
                        if disabled != last_disabled:
                            self.logger.info("sql", "Record %s %s -> %s changed state to %s" % (name, records.type, content, "disabled" if disabled else "enabled"))
                        await self.exl(cursor, "UPDATE records SET disabled = %s, last_lb_check = %s, ttl = %s, prio = %s, last_lb_check_result = %s WHERE id = %s",
                                (disabled, now, records.ttl, en_res.priority, en_res.retcode, id))
                    else:
                        self.logger.info("sql", "Record %s %s -> %s adding new record with state %s" % (name, records.type, content, "disabled" if disabled else "enabled"))
                        await self.exl(cursor, "INSERT INTO records(domain_id, name, type, content, ttl, disabled, last_lb_check, prio, last_lb_check_result)" +
                            " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
                            (self.domain_id, name, records.type, content, records.ttl, disabled, now, en_res.priority, en_res.retcode))
                if len(delete_ids):
                    self.logger.info('sql', 'Deleting old or fallback entries of %s %s: %r' % (name, records.type, delete_ids))
                    await self.exl(cursor, "DELETE FROM records WHERE id IN (" + ",".join(str(i) for i in delete_ids) + ")")
    # }}}
# }}}

def expand_glob(prefix: str, pattern: str, empty_error: Optional[str] = None) ->List[str]: # {{{
    if pattern.startswith('/'):
        ret = glob.glob(pattern)
        err = f"{empty_error}: {pattern} not found."
    else:
        ret = glob.glob(os.path.join(glob.escape(prefix), pattern))
        err = f"{empty_error}: {pattern} not found in {prefix}."
    if len(ret) == 0 and empty_error:
        raise ConfigError(err)
    return [ os.path.realpath(x) for x in ret]
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

        parser.add_argument('-c', '--config',  default=default_cfg_path, help='Configuration file')
        parser.add_argument('-C', '--confdir', default="", help='Included configuration files base path (default: directory of configuration file)')
        parser.add_argument('-t', '--check-config', default=False, action='store_true',
                            help='check configuration file and exit')
        parser.add_argument('-r', '--record-file',  default=cast(List[str],[]), action='append', metavar='FILE',
                            help='Additional record configuration glob pattern (relative to working directory).')
        parser.add_argument('-m', '--mask-record-file', default=cast(List[str],[]), action='append', metavar='FILE',
                            help='Mask recocrd file that will be loaded by global.load_records configuration (relative to config directory).')

        options = parser.parse_args()
        curdir = os.getcwd()
        cfgdir = cast(str, options.confdir)
        if cfgdir == "":
            cfgdir = os.path.dirname(cast(str, options.config))
        record_files = []
        for pat in cast(List[str], options.record_file):
            record_files.extend(expand_glob(curdir, glob.escape(pat), "--record-file error"))
        mask_files_a = []
        for pat in cast(List[str], options.mask_record_file):
            mask_files_a.extend(expand_glob(cfgdir, glob.escape(pat), "--mask-record-file error"))
        mask_files = set(mask_files_a)

        #FIXME parse command line (config file, debug level)
        try:
            with ConfigExtractor(cast(Dict[str, object],
                                      toml.load(cast(str, options.config)))) as config:
                conf_global  = config.section('global')
                conf_sql     = config.section('mysql')
                conf_records = config.section('records')
                conf_default = config.section('default', default=True)

            RecordController('default', 'A', conf_default, None)

            load_paths = None
            with conf_global:
                sql_del_unk = conf_global.bool('delete_unknowns')
                sql_zone    = conf_global.str('domain_name')
                loglevel    = conf_global.str('loglevel')
                self.rclim  = trio.CapacityLimiter(conf_global.int('max_record_checks'))
                try:
                    load_paths  = conf_global.l_str('load_records')
                except MissingConfigError:
                    load_paths = []
                except Exception:
                    load_paths  = [conf_global.str('load_records')]
                for pat in load_paths:
                    record_files.extend([ f for f in
                        expand_glob(cfgdir, pat, None)
                        if f not in mask_files])

            if options.loglevel is not None: # type: ignore
                loglevel = options.loglevel

            self.logger.set_loglevel(loglevel)

            self.sql = SqlController(sql_zone, sql_del_unk, conf_sql, self.logger)

            rcs:Dict[RecordController.Id, RecordController] = {}
            def add_rcs(rcl: List[RecordController]) -> None:
                for rc in rcl:
                    if rc.id() in rcs:
                        raise ConfigError(f"Duplicate entry {rc.name}.{rc.type}")
                    rcs[rc.id()] = rc

            add_rcs(self.parse_records(conf_records, conf_default))

            for rcf in record_files:
                with ConfigExtractor(cast(Dict[str, object], toml.load(rcf)),
                                     section = repr(rcf)) as rconfig:
                    add_rcs(self.parse_records(rconfig, conf_default))

            self.rcs = list(rcs.values())
        except ConfigError as e:
            sys.stderr.write(str(e) + '\n')
            sys.exit(126)

        if options.check_config: #type: ignore
            self.check_config = True
        else:
            self.check_config = False
    # }}}

    def parse_records(self, conf_records: ConfigExtractor, conf_default: ConfigExtractor) -> List[RecordController]: # {{{
        rcs = []
        for name in conf_records:
            r = conf_records.section(name, quote_name = True)
            for t in r:
                if t in ('A', 'AAAA'):
                    rcs.append(RecordController(name, t, r.section(t, default = conf_default), self.logger))
                else:
                    raise Exception(f"Unsupported record type {t} of {name}")
        return rcs
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

    async def handle_reload(self, sigiter: AsyncIterator[int], canceler: trio.CancelScope) -> None: # {{{
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
                    continue # Wait for next SIGUSR1
                self.next_main = new_main
                canceler.cancel()
                return
    # }}}

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

    async def main(self, usr1: AsyncIterator[int]) -> Optional["Main"]: # {{{
        await self.sql.delete_unknown_entries(set([(rc.name, rc.type) for rc in self.rcs]))
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

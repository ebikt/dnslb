# python3

from typing import Dict, Iterable, List, Optional

import os
import socket
import trio

from dnslb.simple_logger    import Logger

class SDNotifier:
    connected: bool     = False
    addr: Optional[bytes] = None
    ignore_exc: bool

    def __init__(self, logger:Logger, addr: Optional[str]=None, ignore_exc: bool = True) -> None:
        self.logger     = logger
        self.ignore_exc = ignore_exc
        if addr is None:
            addr = os.getenv('NOTIFY_SOCKET', None)
        if addr is None or addr == '':
            self.addr = None
        else:
            if addr.startswith('@'):
                addr = '\0' + addr[1:]
        if addr is not None:
            self.addr = addr.encode('utf-8')

    async def _connect(self) -> bool:
        assert self.addr is not None
        try:
            self.socket = trio.socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            await self.socket.connect(self.addr)
            self.connected = True
            return self.connected
        except Exception:
            if self.ignore_exc:
                return False
            else:
                raise

    async def _send(self, message: Iterable[bytes]) -> None:
        if self.addr is None:
            if self.ignore_exc:
                self.logger.debug("sdnotify", "no address specified")
                return
            else:
                raise Exception("Cannot connect to systemd, socket address not found.")
        try:
            if not self.connected:
                await self._connect()
                self.logger.debug("sdnotify", "connected to %r" % (self.addr,))
            if self.connected:
                await self.socket.sendmsg(message)
        except Exception:
            if not self.ignore_exc:
                raise

    async def notify(self, status: Optional[str] = None,
            ready:bool    = False, reloading:bool = False,
            stopping:bool = False, watchdog:Optional[bool] = None,
            extend_timeout: Optional[float] = None,
            notify_timeout: float = 1
        ) -> None:
        lines: Dict[bytes, bytes] = {}
        if status is not None:
            lines[b'STATUS'] = status.encode('utf-8').replace(b'\n', b' ')
        if ready:
            lines[b'READY'] = b'1'
        if reloading:
            lines[b'RELOADING'] = b'1'
        if stopping:
            lines[b'STOPPING'] = b'1'
        if watchdog is not None:
            if watchdog:
                lines[b'WATCHDOG'] = b'1'
            else:
                lines[b'WATCHDOG'] = b'trigger'
        if extend_timeout is not None:
            lines[b'EXTEND_TIMEOUT_USEC'] ="{:.0f}".format( extend_timeout * 1000000 ).encode('ascii')
        message = [b'%s=%s\n' % pair for pair in lines.items()]
        self.logger.debug('sdnotify', 'notify(%r)' % (message,))
        if self.ignore_exc:
            with trio.move_on_after(notify_timeout):
                await self._send(message)
        else:
            with trio.fail_after(notify_timeout):
                await self._send(message)

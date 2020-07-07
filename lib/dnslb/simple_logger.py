# python3

import enum
import sys

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

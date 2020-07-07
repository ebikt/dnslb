# python3

from typing import Dict, Iterator, List, Optional, Set, Type, TypeVar, Union

import json

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

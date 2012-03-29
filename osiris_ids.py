import hashlib
import logging
import socket
import struct

DEFAULT_SCAN_AGENT_PORT = 2265

OSI_DB_ARCHIVE = 0x01
OSI_DB_AUTOACCEPT = 0x04
OSI_DB_PURGE = 0x02
OSI_HOST_TYPE_GENERIC = 0x01
OSI_NOTIFY_AGENT_REKEY = 0x04
OSI_NOTIFY_SCAN_ALWAYS = 0x02
OSI_NOTIFY_SCAN_FAILED = 0x01

MESSAGE_TYPE_CONTROL_DATA_LAST = 0x11
MESSAGE_TYPE_CONTROL_REQUEST = 0x0e
MESSAGE_TYPE_ERROR = 0xef
MESSAGE_TYPE_STATUS_RESPONSE = 0x04
MESSAGE_TYPE_SUCCESS = 0xee

CONTROL_COMMAND_HELLO = 0x01
CONTROL_COMMAND_NEW_HOST = 0x0f
CONTROL_COMMAND_PUSH_CONFIG = 0x03
CONTROL_COMMAND_REMOVE_HOST = 0x24
CONTROL_COMMAND_START_SCAN = 0x05
CONTROL_COMMAND_STATUS = 0x02
CONTROL_COMMAND_UNSET_BASE_DATABASE = 0x1e

HOST_SESSION_KEY_LENGTH = 64
MAX_AUTH_PASSWORD_LENGTH = 20
MAX_AUTH_USERNAME_LENGTH = 20
MAX_CHECKSUM_LENGTH = 41
MAX_ERROR_MESSAGE_LENGTH = 512
MAX_HELLO_MESSAGE_LENGTH = 256
MAX_HELLO_VERSION_LENGTH = 20
MAX_HOST_BRIEF_CONFIG_LENGTH = 64
MAX_HOST_BRIEF_DB_NAME_LENGTH = 10
MAX_HOST_BRIEF_DESCRIPTION_LENGTH = 255
MAX_HOST_BRIEF_NAME_LENGTH = 128
MAX_HOST_BRIEF_NOTIFY_EMAIL_LENGTH = 128
MAX_PATH_LENGTH = 256
MAX_STATUS_OS_NAME_LENGTH = 30
MAX_STATUS_OS_VERSION_LENGTH = 20
MAX_STATUS_VERSION_LENGTH = 20

logger = logging.getLogger(__name__)


# Exceptions ###########################################################

class OsiError(Exception):
    def __init__(self, payload):
        self.payload = payload

    def __repr__(self):
        return '%s.%s(payload=%r)' % (
          self.__module__, self.__class__.__name__, self.payload)

    def __str__(self):
        return self.payload.message


# Building block data structures #######################################

class Payload(object):
    PAYLOAD_FMT = ('', [],)

    def __getattr__(self, name):
        if '_values' in self.__dict__.keys():
            return self._values[name]
        raise AttributeError()

    def __init__(self, *args, **kwargs):
        self._values = {}
        self._build_values(*args, **kwargs)
        self._strip_nulls()

    def __repr__(self):
        kv = ', '.join(map(lambda (k, v): '%s=%r' % (k, v),
          zip(self.field_names(), self.field_values())))
        return '%s.%s(%s)' % (
          self.__module__, self.__class__.__name__, kv)

    def __setattr__(self, name, value):
        try:
            if name in self._values.keys():
                self._values[name] = value
                return
        except AttributeError:
            pass
        object.__setattr__(self, name, value)

    def _build_values(self, *args, **kwargs):
        assert isinstance(self._values, dict)
        if len(kwargs.keys()) == 0:
            i = 0
            for fn in self.field_names():
                try:
                    self._values[fn] = args[i]
                except IndexError:
                    raise Exception("Missing payload field: %s" % fn)
                i += 1
        else:
            for fn in self.field_names():
                if fn in kwargs:
                    self._values[fn] = kwargs[fn]
                else:
                    raise Exception("Missing payload field: %s" % fn)

    def _strip_nulls(self):
        """Remove trailing nulls from unpacked structs."""
        FORMAT_CHARACTERS = 'cbB?hHiIlLqQfdspP'
        i = 0
        for c in self.format():
            if c in FORMAT_CHARACTERS:
                if c == 's':
                    fn = self.field_names()[i]
                    padded = self._values[fn]
                    stripped = padded.rstrip('\x00')
                    self._values[fn] = stripped
                i += 1

    @classmethod
    def field_names(klass):
        return klass.PAYLOAD_FMT[1]

    def field_values(self):
        return [self._values[fn] for fn in self.field_names()]

    @classmethod
    def format(klass):
        return klass.PAYLOAD_FMT[0]

    @classmethod
    def deserialise(klass, payload):
        if klass.format() != '':
            logger.debug("Deserialising payload %r with %r." % (
              payload, klass.format()))
            return klass(*struct.unpack(klass.format(), payload))
        else:
            return None

    def serialise(self):
        logger.debug("Serialising payload %r with %r." % (
          self.field_values(), self.format()))
        return struct.pack(self.format(), *self.field_values())

class Message(object):
    # Type        (2 bytes)
    # Length      (2 bytes)  Does not include header.
    # Sequence no (2 bytes)
    # Padding     (2 bytes)
    # Payload     (variable)
    HEADER_FMT = '!HHHH'

    def __init__(self, type, sequence, payload, length=None):
        self.type = type
        self.sequence = sequence
        self.payload = payload
        if length is None:
            self.length = struct.calcsize(self.payload.format())
        else:
            self.length = length

    def __repr__(self):
        return '%s.%s(type=%r, sequence=%r, payload=%r, length=%r)' % (
          self.__module__, self.__class__.__name__,
          self.type, self.sequence, self.payload, self.length)

    @classmethod
    def deserialise(klass, pdu, payload_klass=Payload):
        type, length, sequence, padding = struct.unpack(
          klass.HEADER_FMT, pdu[0:8])
        if type == MESSAGE_TYPE_ERROR:
            payload = ErrorPayload.deserialise(pdu[8:])
            raise OsiError(payload)
        else:
            payload = payload_klass.deserialise(pdu[8:])
        return klass(type=type, sequence=sequence, payload=payload,
          length=length)

    def serialise(self):
        header = struct.pack(
          self.HEADER_FMT, self.type, self.length, 0, 0)
        return header + self.payload.serialise()


# Payload formats ######################################################

class AuthenticationRequestPayload(Payload):
    OSI_AUTH_CONTEXT = '%ds%ds' % (
      MAX_AUTH_USERNAME_LENGTH, MAX_AUTH_PASSWORD_LENGTH)
    PAYLOAD_FMT = (
        OSI_AUTH_CONTEXT,
        ['username', 'password',],
    )

    def __init__(self, *args, **kwargs):
        Payload.__init__(self, *args, **kwargs)

class ControlRequestPayload(Payload):
    OSI_CONTROL_REQUEST = '!Q%ds%ds' % (
      MAX_HOST_BRIEF_NAME_LENGTH, MAX_PATH_LENGTH)
    PAYLOAD_FMT = (
        OSI_CONTROL_REQUEST,
        ['command', 'host', 'buffer',],
    )

    def __init__(self, *args, **kwargs):
        Payload.__init__(self, *args, **kwargs)

class ErrorPayload(Payload):
    OSI_ERROR = '!QQ%ds' % MAX_ERROR_MESSAGE_LENGTH
    PAYLOAD_FMT = (
        OSI_ERROR,
        ['type', 'time', 'message',],
    )

    def __init__(self, *args, **kwargs):
        Payload.__init__(self, *args, **kwargs)

class HelloResponsePayload(Payload):
    OSI_HELLO_RESPONSE = '%ds%ds' % (
      MAX_HELLO_VERSION_LENGTH, MAX_HELLO_MESSAGE_LENGTH)
    PAYLOAD_FMT = (
        OSI_HELLO_RESPONSE,
        ['version', 'message',],
    )

    def __init__(self, *args, **kwargs):
        Payload.__init__(self, *args, **kwargs)

class HostBriefPayload(Payload):
    OSI_HOST_BRIEF = ''.join([
      '!Q',  # osi_uint64 enabled
       'Q',  # osi_uint64 type
       'Q',  # osi_uint64 file_log_enabled
       'Q',  # osi_uint64 db_flags
       'Q',  # osi_uint64 notify_enabled
       'Q',  # osi_uint64 notify_flags
       'Q',  # osi_uint64 config_count
       'Q',  # osi_uint64 database_count
       'Q',  # osi_uint64 schedule_start
       'Q',  # osi_uint64 schedule_period
       'Q',  # osi_uint64 port
       '8x', # osi_uint64 unused
       '%ds' % MAX_HOST_BRIEF_NAME_LENGTH,         # name
       '%ds' % MAX_HOST_BRIEF_NAME_LENGTH,         # host
       '%ds' % MAX_HOST_BRIEF_DESCRIPTION_LENGTH,  # description
       '%ds' % HOST_SESSION_KEY_LENGTH,            # session_key
       '%ds' % MAX_HOST_BRIEF_DB_NAME_LENGTH,      # base_db
       '%ds' % MAX_HOST_BRIEF_NOTIFY_EMAIL_LENGTH, # notify_email
       '%ds' % MAX_HOST_BRIEF_CONFIG_LENGTH,       # config
    ])
    PAYLOAD_FMT = (
        OSI_HOST_BRIEF,
        [
            'enabled',
            'type',
            'file_log_enabled',
            'db_flags',
            'notify_enabled',
            'notify_flags',
            'config_count',
            'database_count',
            'schedule_start',
            'schedule_period',
            'port',
            'name',
            'host',
            'description',
            'session_key',
            'base_db',
            'notify_email',
            'config',
        ],
    )

    def __init__(self, *args, **kwargs):
        debooleanise_params = (
            'enabled',
            'file_log_enabled',
            'notify_enabled',
        )
        debooleanised_args = dict(
          [(k, debooleanise(kwargs[k])) for k in debooleanise_params])

        auto_params = filter(
          lambda k: k not in debooleanise_params, kwargs.keys())
        auto_args = dict([(k, kwargs[k]) for k in auto_params])

        Payload.__init__(self, *args,
          **(dict(auto_args.items() + debooleanised_args.items())))

class StatusResponsePayload(Payload):
    OSI_STATUS = ''.join([
      '!L',  # osi_uint32 start_time
       'L',  # osi_uint32 current_time
       'L',  # osi_uint32 config_time
       'H',  # osi_uint16 config_state
       'H',  # osi_uint16 daemon_state
       '%ds' % MAX_STATUS_VERSION_LENGTH,    # osiris_version
       '%ds' % MAX_CHECKSUM_LENGTH,          # config_id
       '%ds' % MAX_STATUS_OS_NAME_LENGTH,    # os_name
       '%ds' % MAX_STATUS_OS_VERSION_LENGTH, # os_version
       'H',  # osi_uint16 reserved1
       'H',  # osi_uint16 reserved2
       '1c', # alignment
    ])
    PAYLOAD_FMT = (
        OSI_STATUS,
        [
            'start_time',
            'current_time',
            'config_time',
            'config_state',
            'daemon_state',
            'osiris_version',
            'config_id',
            'os_name',
            'os_version',
            'reserved1',
            'reserved2',
            'alignment1',
        ],
    )

    def __init__(self, *args, **kwargs):
        Payload.__init__(self, *args, **kwargs)


# Request messages #####################################################

class AuthenticationRequest(Message):
    def __init__(self, username, password):
        type = MESSAGE_TYPE_CONTROL_REQUEST
        payload = AuthenticationRequestPayload(username, password)
        Message.__init__(self, type, 0, payload)

class ControlRequest(Message):
    def __init__(self, command, host="", buffer=""):
        type = MESSAGE_TYPE_CONTROL_REQUEST
        payload = ControlRequestPayload(command, host, buffer)
        Message.__init__(self, type, 0, payload)

class NewHostRequest(Message):
    def __init__(self, host, description, notify_email):
        type = MESSAGE_TYPE_CONTROL_DATA_LAST
        payload = HostBriefPayload.new_host(
          host, description, notify_email)
        Message.__init__(self, type, 0, payload)

class StatusRequest(Message):
    def __init__(self, host):
        type = MESSAGE_TYPE_CONTROL_REQUEST
        command = CONTROL_COMMAND_STATUS
        payload = ControlRequestPayload(command, host, "")
        Message.__init__(self, type, 0, payload)


# Response messages ####################################################

class HelloResponse(Message):
    @classmethod
    def deserialise(klass, pdu, _):
        return Message.deserialise(pdu, HelloResponsePayload)

class StatusResponse(Message):
    @classmethod
    def deserialise(klass, pdu, _):
        return Message.deserialise(pdu, StatusResponsePayload)


########################################################################

class OsirisCtl(object):
    dump_raw = False

    def __init__(self, username, password, host='127.0.0.1', port=2266):
        self.host = socket.gethostbyname(host)
        self.port = port
        self.username = username
        self.password_hash = sha1(password)
        self.s = None

    def authenticate(self):
        logger.debug("Authenticating as %s..." % self.username)
        self.say(AuthenticationRequest(username=self.username,
          password=self.password_hash))
        try:
            resp = self.hear()
        except socket.sslerror, e:
            # The server will break contact as soon as it receives a bad 
            # password from us.
            if e.args[0] == 6:
                raise Exception(
                  "Authentication failed.  Check your credentials.")
            else:
                raise
        assert resp.type == MESSAGE_TYPE_SUCCESS
        logger.debug("Authenticated.")

    def connect(self):
        logger.info("Connecting to %s:%d..." % (self.host, self.port))
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((self.host, self.port,))
        self.ssl = socket.ssl(self.s)
        logger.info("Connected.")
        self.authenticate()
        self.say_hello()
        logger.info("Ready.")

    def close(self):
        self.ssl = None
        self.s.close()
        self.s = None
        logger.info("Disconnected from %s:%d." % (self.host, self.port))

    def hear(self, klass=Message, payload_klass=Payload):
        raw = self.ssl.read()
        if self.dump_raw:
            logger.debug(repr(raw))
        what = klass.deserialise(raw, payload_klass)
        logger.debug("Read from socket: %r" % what)
        return what

    def new_host(self, host, description, notify_email):
        self.say(ControlRequest(command=CONTROL_COMMAND_NEW_HOST))
        self.say(NewHostRequest(host, description, notify_email))
        resp = self.hear()
        assert resp.type == MESSAGE_TYPE_SUCCESS
        logger.info("Added new host %s." % host)

    def push_config(self, host, config):
        self.say(ControlRequest(
          command=CONTROL_COMMAND_PUSH_CONFIG, host=host, buffer=config))
        resp = self.hear()
        assert resp.type == MESSAGE_TYPE_SUCCESS
        logger.info("Pushed config %s to %s." % (config, host))

    def remove_host(self, host):
        self.say(ControlRequest(
          command=CONTROL_COMMAND_REMOVE_HOST, host=host))
        resp = self.hear()
        assert resp.type == MESSAGE_TYPE_SUCCESS
        logger.info("Removed host %s." % host)

    def say(self, what):
        logger.debug("Write to socket: %r" % what)
        raw = what.serialise()
        if self.dump_raw:
            logger.debug(repr(raw))
        self.ssl.write(raw)

    def say_hello(self):
        logger.debug("Greeting the server...")
        self.say(ControlRequest(command=CONTROL_COMMAND_HELLO))
        resp = self.hear(HelloResponse)
        logger.debug("Server version %s greeted us back with: %s" %
          (resp.payload.version, resp.payload.message))

    def start_scan(self, host):
        self.say(ControlRequest(
          command=CONTROL_COMMAND_START_SCAN, host=host))
        resp = self.hear()
        assert resp.type == MESSAGE_TYPE_SUCCESS
        logger.info("Started scan on %s." % host)

    def status(self, host):
        self.say(StatusRequest(host=host))
        try:
            resp = self.hear(StatusResponse)
        except OsiError:
            # Common problems:
            #
            # "no host specified.":
            #
            #     Configure the new host first.  See OsirisCtl. 
            #     new_host().
            #
            # "unable to connect to host.":
            #
            #     Target host or osirisd agent on target host might be 
            #     down.  If that definitely is not the problem, check 
            #     your firewalls.
            #
            raise
        assert resp.type == MESSAGE_TYPE_STATUS_RESPONSE
        logger.info("%s is alive." % host)
        return resp.payload

    def unset_base(self, host):
        self.say(ControlRequest(
          command=CONTROL_COMMAND_UNSET_BASE_DATABASE, host=host))
        resp = self.hear()
        assert resp.type == MESSAGE_TYPE_SUCCESS
        logger.info("Unset trusted baseline on %s." % host)

def debooleanise(input):
    if isinstance(input, bool):
        if input == True:
            return 1
    elif isinstance(input, int):
        if input > 0:
            return 1
    elif isinstance(input, str):
        if input.lower().startswith("y"):
            return 1
    else:
        raise ValueError
    return 0

def sha1(plaintext):
    """Python implementation of Osiris' sha1_buffer()."""
    # -1 because the C implementation reserves space for the string 
    # terminator.
    prefix = plaintext[0:(MAX_AUTH_PASSWORD_LENGTH - 1)]
    return hashlib.sha1(prefix).hexdigest() \
      [0:(MAX_AUTH_PASSWORD_LENGTH - 1)]

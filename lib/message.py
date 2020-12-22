import binascii
import datetime

from lib.cryptohelper import CryptoHelper


class MessageBase(object):
    def __init__(self, domain: str):
        self.c = CryptoHelper()
        self._domain = domain
        self._raw = domain.split('.')[0].encode()
        self._raw_decrypted = self.c.decrypt_secure_string(self.c.decode32(self._raw))
        self.validate()

    @property
    def user_id(self):
        return binascii.hexlify(self._raw_decrypted[:8]).decode()

    def validate(self):
        # See CryptoHelper.GetStatus
        regions = [
            "eu-west-1",
            "us-west-2",
            "us-east-1",
            "us-east-2"
        ]
        region = self._domain.split('.')[2]
        if region[self.user_id.encode()[0] % len(regions)] not in self._domain:
            raise ValueError('Message parsing error encountered: GUID/Region check failed.')


class TimestampMessage(MessageBase):
    def __str__(self):
        return f'<MsgType1 Domain={self._domain} UserId={self.user_id} Timestamp={self.timestamp}>'

    def validate(self):
        if len(self._raw_decrypted) != 11 or self._raw_decrypted[8] >> 4 != 1:
            raise ValueError('Message parsing error encountered: data is not a valid TimestampMessage')
        super().validate()

    @property
    def minutes(self):
        return (((self._raw_decrypted[8] & 0x0f) << 16 | (self._raw_decrypted[9] << 8) | self._raw_decrypted[
            10]) >> 1) * 30

    @property
    def user_id(self):
        user_id = bytearray(binascii.unhexlify(super().user_id.encode()))
        for k, _ in enumerate(user_id):
            user_id[k] ^= self._raw_decrypted[len(user_id) + 2 - k % 2]
        return binascii.hexlify(user_id).decode()

    @property
    def timestamp(self):
        return (datetime.datetime(year=2010, month=1, day=1) + datetime.timedelta(minutes=self.minutes)).strftime(
            '%Y-%m-%d %H:%M:%S')


class ServiceStatusMessage(TimestampMessage):
    def __str__(self):
        return f'<MsgType2 Domain={self._domain} UserId={self.user_id} Timestamp={self.timestamp} ServiceStatuses={self.service_statuses[:15] + "..."}>'

    def validate(self):
        if len(self._raw_decrypted) < 13 or self._raw_decrypted[8] >> 4 != 2:
            raise ValueError('Message parsing error encountered: data is not a valid ServiceStatusMessage')
        super(TimestampMessage, self).validate()

    @property
    def service_statuses(self):
        i = 0
        output = ''
        while i < len(self._raw_decrypted) * 8 - 1:
            output += f'{(self._raw_decrypted[i // 8] >> (i % 8)) & 1}{(self._raw_decrypted[(i + 1) // 8] >> ((i + 1) % 8)) & 1} '  # Displays Running? Stopped? in that order
            i += 2
        return output


class HostnameMessage(MessageBase):
    def __str__(self):
        return f'<MsgType3 Domain={self._domain} UserId={self.user_id} SequenceNumber:{self.seq} HostName={self.hostname}>'

    @property
    def user_id(self):
        user_id = self._raw_decrypted[:8]
        return binascii.hexlify(user_id).decode()

    @property
    def seq(self):
        return self.c.get_seq(self._raw[15], self._raw[0])

    @property
    def hostname(self):
        """ reverses CryptoHelper.DecryptShort """
        input_data = self._raw[16:]
        suffix = b''
        if input_data.endswith(b'0') and not input_data.endswith(b'00'):
            # see CryptoHelper.GetPreviousString
            suffix = b'<truncated>'
            input_data = input_data[:-1]
        if input_data.startswith(b'00'):
            return (self.c.decode32(input_data[2:]) + suffix).decode()
        else:
            return (self.c.decode35(input_data) + suffix).decode()

import random


class CryptoHelper(object):
    B32_ALPHABET = b'ph2eifo3n5utg1j8d94qrvbmk0sal76c'  # 0123456789abcdefghijklmnopqrstuv
    B35_ALPHABET = b'rq3gsalt6u1iyfzop572d49bnx8cvmkewhj'  # 123456789abcdefghijklmnopqrstuvwxyz
    B35_BADCHARS = b'0_-.'

    def __init__(self):
        return

    def encode35(self, input_data: bytes):
        """ Implements CryptoHelper:Base64Decode """
        output = bytearray()
        for c in input_data:
            if c not in self.B35_BADCHARS:
                index = (self.B35_ALPHABET.find(c) + 4) % len(self.B35_ALPHABET)
                output.append(self.B35_ALPHABET[index])
            else:
                output.append(self.B35_BADCHARS[0])
                output.append(self.B35_ALPHABET[self.B35_BADCHARS.find(c) + random.randint(0, len(self.B35_ALPHABET) // len(self.B35_BADCHARS)) * len(self.B35_BADCHARS)])
        return bytes(output)

    def decode35(self, input_data: bytes):
        output = bytearray()
        position = 0
        while position < len(input_data):
            ch = input_data[position]
            if ch == self.B35_BADCHARS[0]:
                position += 1
                ch = input_data[position]
                index = self.B35_ALPHABET.find(ch) % len(self.B35_BADCHARS)
                output.append(self.B35_BADCHARS[index])
            else:
                index = (self.B35_ALPHABET.find(input_data[position]) - 4) % len(self.B35_ALPHABET)
                output.append(self.B35_ALPHABET[index])
            position += 1
        return bytes(output)

    def encode32(self, input_data: bytes, rt: bool=False):
        """ Implements CryptoHelper.Base64Encode """
        output = bytearray()
        register = 0
        register_bitlen = 0
        for c in input_data:
            register |= c << register_bitlen
            register_bitlen += 8
            while register_bitlen >= 5:
                output.append(self.B32_ALPHABET[register & 0x1f])
                register >>= 5
                register_bitlen -= 5
        if register_bitlen > 0:
            if rt:
                register |= random.randint(0, 255) << register_bitlen
            output.append(self.B32_ALPHABET[register & 0x1f])
        return bytes(output)

    def decode32(self, input_data: bytes):
        output = bytearray()
        register = 0
        register_bitlen = 0
        for c in input_data:
            register |= self.B32_ALPHABET.find(c) << register_bitlen
            register_bitlen += 5
            while register_bitlen >= 8:
                output.append(register & 0xff)
                register >>= 8
                register_bitlen -= 8
        return bytes(output)

    def create_secure_string(self, input_data: bytes, non_printable: bool=False):
        """ Implements CryptoHelper.CreateSecureString """
        output = bytearray([random.randint(0, 127)]) + bytearray(input_data)
        if non_printable:
            output[0] |= 0x80
        for k, v in enumerate(input_data):
            output[k + 1] = output[0] ^ v
        return self.encode32(bytes(output))

    def decrypt_secure_string(self, input_data: bytes):
        output = bytearray(input_data[1:])
        for k, v in enumerate(output):
            output[k] = input_data[0] ^ v
        return output

    def create_string(self, n: int, c: int):
        """ Implements CryptoHelper.CreateString """
        if n < 0 or n >= 36:
            n = 35
        n = (n + c) % 36
        if n < 10:
            return bytes([0x30 + n])
        else:
            return bytes([0x61 + n - 10])

    def get_seq(self, n: int, c: int):
        """ reverses self.create_string """
        if b'0'[0] <= n <= b'9'[0]:
            n -= b'0'[0]
        elif b'a'[0] <= n <= b'z'[0]:
            n -= b'a'[0]
        else:
            raise ValueError('Expected a value in 0-9a-z')
        return (c - n) % 36

    def encode_domain(self, input_data: bytes):
        """ Implements CryptoHelper.DecryptShort """
        if all([c in self.B35_ALPHABET + self.B35_BADCHARS for c in input_data]):
            return self.encode35(input_data)
        else:
            return b'00' + self.encode32(input_data, False)

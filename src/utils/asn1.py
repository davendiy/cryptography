#!/usr/bin/env python3
# -*-encoding: utf-8-*-

# created: 29.05.2020
# Excusa. Quod scripsi, scripsi.

# by David Zashkolny
# 3 course, comp math
# Taras Shevchenko National University of Kyiv
# email: davendiy@gmail.com

from math import ceil
from abc import abstractmethod, ABC
from typing import Tuple, Any
from array import array


class TagError(ValueError):

    def __init__(self, der_type):
        super().__init__()
        self._type = der_type

    def __str__(self):
        return f"Error tag for {self._type} object."


class ZeroLenError(ValueError):

    def __str__(self):
        return "Zero-len data error."


class LengthError(ValueError):
    pass


class BodyDecodingError(ValueError):
    pass


class InvalidOID(ValueError):
    pass


def _int_bytes_len(num, byte_len=8):
    if num == 0:
        return 1
    return int(ceil(float(num.bit_length()) / byte_len))


def _len_encode(length):
    if length < 0x80:
        return bytes([length])
    octets = bytearray(_int_bytes_len(length) + 1)
    octets[0] = 0x80 | (len(octets) - 1)
    for i in range(len(octets) - 1, 0, -1):
        octets[i] = length & 0xFF
        length >>= 8
    return bytes(octets)


def _len_decode(data: bytes):
    """Decode length

    :returns: (decoded length, length's length, remaining data)
    :raises LenIndefForm: if indefinite form encoding is met
    """
    if len(data) == 0:
        raise ZeroLenError()
    first_octet = data[0]
    if first_octet & 0x80 == 0:
        return first_octet, 1, data[1:]
    octets_num = first_octet & 0x7F
    if octets_num + 1 > len(data):
        raise LengthError("Encoded length is longer than data.")
    if octets_num == 0:
        raise LengthError("Bad encoded length.")
    if data[1] == 0:
        raise BodyDecodingError("Leading zeros.")
    length = 0
    for v in data[1:1 + octets_num]:
        length = (length << 8) | v
    if length <= 127:
        raise BodyDecodingError("Long form instead of short one")
    return length, 1 + octets_num, data[1 + octets_num:]


def zero_ended_encode(num):
    octets = bytearray(_int_bytes_len(num, 7))
    i = len(octets) - 1
    octets[i] = num & 0x7F
    num >>= 7
    i -= 1
    while num > 0:
        octets[i] = 0x80 | (num & 0x7F)
        num >>= 7
        i -= 1
    return bytes(octets)


def zero_ended_decode(stream: bytes) -> Tuple[int, int, bytes]:
    if not stream:
        raise ZeroLenError()
    res = 0
    for i, el in enumerate(stream):
        res <<= 7
        res += el & 0x7F
        if not el & 0x80:
            break

    if el & 0x80:
        raise BodyDecodingError("There is no end of zero-ended code.")
    return res, i + 1, stream[i+1:]


class DerObj(ABC):

    _tag = None

    def __init__(self, value=None):
        self.value = value

    @abstractmethod
    def _internal_encode(self) -> bytes:
        pass

    def encode(self) -> bytes:
        body = self._internal_encode()
        return b''.join((self._tag, _len_encode(len(body)), body))

    @abstractmethod
    def _internal_decode(self, stream: bytes, length: int):
        pass

    @classmethod
    def decode(cls, stream: bytes) -> Tuple[Any, int, bytes]:
        if stream[0] != ord(cls._tag):
            raise TagError(cls)

        length, llen, _ = _len_decode(stream[1:])
        obj = cls()
        obj._internal_decode(stream[llen + 1:], length)
        return obj, length + llen + 1, stream[length + llen + 1:]


class DerInteger(DerObj):

    _tag = b'\x02'

    def __init__(self, value=0):
        if isinstance(value, int):
            super().__init__(value)
        else:
            raise TypeError("Bad input parameter's type.")

    def _internal_encode(self):
        value = self.value
        bytes_len = ceil(value.bit_length() / 8) or 1
        while True:
            try:
                octets = value.to_bytes(
                    bytes_len,
                    byteorder="big",
                    signed=True,
                )
            except OverflowError:
                bytes_len += 1
            else:
                break

        return octets

    def _internal_decode(self, stream: bytes, length):
        self.value = int(stream[:length].hex(), 16)

    def __str__(self):
        return f'IntegerDER({self.value})'

    def __repr__(self):
        return f'IntegerDER({self.value})'


class DerObjectIdentifier(DerObj):

    _tag = b'\x06'

    def __init__(self, value=''):
        if value:
            value = self._value_sanitize(value)
        super().__init__(value)

    @staticmethod
    def _value_sanitize(value):
        if issubclass(value.__class__, DerObjectIdentifier):
            return value.value
        if isinstance(value, str):
            try:
                value = array("L", (int(arc) for arc in value.split(".")))
            except ValueError:
                raise InvalidOID("unacceptable arcs values")
        if value.__class__ == tuple:
            try:
                value = array("L", value)
            except OverflowError as err:
                raise InvalidOID(repr(err))
        if value.__class__ is array:
            if len(value) < 2:
                raise InvalidOID("less than 2 arcs")
            first_arc = value[0]
            if first_arc in (0, 1):
                if not (0 <= value[1] <= 39):
                    raise InvalidOID("second arc is too wide")
            elif first_arc == 2:
                pass
            else:
                raise InvalidOID("unacceptable first arc value")
            if not all(arc >= 0 for arc in value):
                raise InvalidOID("negative arc value")
            return value
        raise TypeError("Bad value's type for Object Itendifier.")

    def _internal_encode(self) -> bytes:
        value = self.value
        first_value = value[1]
        first_arc = value[0]
        if first_arc == 0:
            pass
        elif first_arc == 1:
            first_value += 40
        elif first_arc == 2:
            first_value += 80
        else:  # pragma: no cover
            raise RuntimeError("invalid arc is stored")
        octets = [zero_ended_encode(first_value)]
        for arc in value[2:]:
            octets.append(zero_ended_encode(arc))
        return b"".join(octets)

    def _internal_decode(self, stream: bytes, length: int):
        handled = 0
        value = []
        while handled < length:
            tmp_val, tmp_len, stream = zero_ended_decode(stream)
            handled += tmp_len
            value.append(tmp_val)

        if value:
            first_value = value[0]
            if first_value > 80:
                first_arc = 2
                first_value -= 80
            elif first_value > 40:
                first_arc = 1
                first_value -= 40
            else:
                first_arc = 0
            value = [first_arc, first_value] + value[1:]

        value = array('L', value)
        value = self._value_sanitize(value)
        self.value = value

    def __str__(self):
        return f"DerObjectIdentifier({'.'.join(map(str, self.value))})"

    def __repr__(self):
        return '.'.join(map(str, self.value))


class DerOctedString(DerObj):

    _tag = None

    def encode(self) -> bytes:
        return self.value

    def _internal_encode(self) -> bytes:
        pass

    def _internal_decode(self, stream: bytes, length: int):
        self.value = stream[:length]

    def __str__(self):
        return f'DerOctedString({self.value})'

    def __repr__(self):
        return f'DerOctedString({self.value})'


class DerNull(DerObj):

    _tag = b'\x05'

    __created = None

    # pattern singleton
    def __new__(cls):
        if cls.__created is None:
            cls.__created = super().__new__(cls)
        return cls.__created

    def __init__(self):
        super().__init__()
        self.value = None

    def _internal_decode(self, stream: bytes, length: int):
        pass

    def _internal_encode(self) -> bytes:
        pass

    def encode(self) -> bytes:
        return b'\x05\x00'

    @classmethod
    def decode(cls, stream: bytes) -> Tuple[Any, int, bytes]:
        if not stream.startswith(b'\x05\x00'):
            raise BodyDecodingError("Bad stream for Null value.")

        return cls(), 2, stream[2:]

    def __str__(self):
        return "DerNull()"

    def __repr__(self):
        return "DerNull()"


class DerSequence(DerObj):
    
    _tag = b'\x30'
    _type = list

    # now only integer type is implemented
    __possible_types = {
        int: DerInteger,
    }

    __possible_tags = {
        0x02: DerInteger,
        0x05: DerNull,
        0x04: DerOctedString,
        0x06: DerObjectIdentifier
    }

    def __new__(cls, *args, **kwargs):
        if cls._tag not in cls.__possible_tags:
            cls.__possible_tags[cls._tag[0]] = cls
            cls.__possible_types[cls._type] = cls
        return super().__new__(cls)

    def __init__(self, value=None):
        if value is None:
            super().__init__([])
        elif isinstance(value, list):
            super().__init__(value)
        else:
            raise TypeError("Bad input parameter's type.")
        
    def _internal_encode(self) -> bytes:
        octets = b''
        for el in self.value:
            if el is None:
                continue
            elif isinstance(el, DerObj):
                octets += el.encode()
            elif type(el) in self.__possible_types:
                octets += self.__possible_types[type(el)](el).encode()
            else:
                raise NotImplementedError()
        return octets
    
    def _internal_decode(self, stream: bytes, length: int):
        self.value = []
        handled = 0
        while handled < length:
            if not stream:
                raise LengthError("Stream is too short for the given length.")
            if stream[0] in self.__possible_tags:
                derClass = self.__possible_tags[stream[0]]
                tmp_obj, tmp_handled, stream = derClass.decode(stream)
                handled += tmp_handled
                self.value.append(tmp_obj)
            else:
                raise TagError(list(self.__possible_tags.values()))

    def __delitem__(self, n):
        del self.value[n]

    def __getitem__(self, n):
        return self.value[n]

    def __setitem__(self, key, value):
        self.value[key] = value

    def __setslice__(self, i, j, sequence):
        self.value[i:j] = sequence

    def __delslice__(self, i, j):
        del self.value[i:j]

    def __getslice__(self, i, j):
        return self.value[max(0, i):max(0, j)]

    def __iter__(self):
        return iter(self.value)

    def __add__(self, other):
        if isinstance(other, DerSequence):
            self.value += other.value
        elif isinstance(other, list):
            self.value += other
        else:
            raise ValueError(f"Can't add {type(other)} to the SequenceDER object.")

    def __len__(self):
        return len(self.value)

    def append(self, item):
        return self.value.append(item)

    def __str__(self):
        return f"SequenceDER({self.value})"

    def __repr__(self):
        return f"SequenceDER({self.value})"

    def __bytes__(self):
        return self.encode()


if __name__ == '__main__':
    test = [DerObjectIdentifier('1.2.840.113549.1.1.1'), DerNull(), DerOctedString(b'\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01'),
            1, 4, 2123123123123123123123,
            3984759834759824978523983453453453453453453453453453453453453453453453453453453445347592834759837459872395855737249857932847593847459837598347598347593844758934759238475982375983745983247598324759832745938475983475923847592345,
            [1, 2, 3, 4], 1241242353453]
    encoded = DerSequence(test).encode()
    print(encoded)

    decoded, _, _ = DerSequence().decode(encoded)
    print(decoded)

    print(DerObjectIdentifier('1.2.840.113549.1.1.1').encode().hex())

    test2 = DerSequence([0,
        2888101424267182350887521861928062988881089034858860357004227582416057146794249188766641780372754541180888376848546613818541632397406242675992249086999192678056555292486726592444581746088863460960501001950106300014129058590763506180752675885304719066401399314197891604565867479952946749335262768578482815401358286893218217359552635941461342478135657108134467017980166642408565219313507504031331459364579194451206735564896045085084723764575205719026501858038872467842296479080256383317126062068509099776122836153950111467545927336577158041916180968653447527443365039066882201276135073808634654746140254529482612631093,

        62823061791729572044239281052958001604688037715787224957503261954084727619821699623802519729192391653239483515067484983910803006425651137994519786444593443415994094641265151415849391546327003767176965568187369831161778200961087766804431481632745171930164395019332122323339851249992954462629283923263737865953,

        24629978416369648489290350235548692232183835619778000635038252627972224620719171400117981891659057186685675205131814814290019917924670618852533875603008638199119345312252583676986899970320202743304515019910443341429037221341340296233899917692362542169817881088964631163676390414380397317585991733672396775989,

        65537,

        46539833548610358920608684599257306147602638819165264621830849045685059559738064687533661755664916244251753516971526783827332914292798850813008121075649395264763330268921219741588530586040286363650935373691693283507739393376657955389227469755400878646360586883350681605220864773463553260679890844437675995318564165660949764594630087578460690897427492827771152008038061820427086683181654648147300237321536223256550920928355660025371163741500718969797533872517254631795991062101913543093175095690436979054271630130703646862610272981154571428384042729298486573633036283571103803299925790064007778672828575216902281269149,

        257584772312598909100557417565547331779682177663885595723216421339142316943209129644966575043298409145292544489926036248158301841348717381803481183947655186508633945226763903174457055416143196064156455983627105644697788911185360921738114740475802072872071068342215296590635875336010276314898359639573047329891,

        180677736229417691184533432212576073743074998322519680727389966697942207854048839942862343769158230450393899252151751453338374228904089808343240721445531354561863055040194490311024229164414050502344750488008811872311933330540342399180781162503286761381615678635266961335780120728368938773520611176369808317439,

        117268211827454772826623165897002440898759601495780180219561792708866172729447352818964566928205404116482123912500407921432678061992242757088283963020599443123206932460179411864376820515052986280425203815028293012010840667642998860709873881585090054755863798384678324074402510749387553424946692087323564164954,
    ])

    # test3 = []
    #
    encoded = test2.encode()
    print(encoded)
    x, _, _ = DerSequence.decode(encoded)

    for _x, _y in zip(x, test2):
        if _x.value != _y:
            print(False)
            break
    print(True)

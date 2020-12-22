# YASDGAD - Yet Another Sunburst DGA Decoder

Malware from the recent sunburst campaign encoded C2 data in DNS requests and responses. Early tools to decode these comms did a good job of revealing the hostnames of compromised systems, especially:

- https://github.com/RedDrip7/SunBurst_DGA_Decode

Another researcher noted that multiple requests could be correlated using an 8-byte user-id string encoded at the beginning of the request:

- https://github.com/CaptanMoss/FireeyeSUNBURST-StringDecoder

This tool made me curious about the protocol being used, so I dug in deeper and this is the result. Notable improvements include

- Decode all avsvmcloud.com domains
- Sanity checking to ensure domains are decoding properly
- Hints on how hostname fragments can be reassembled programmatically
- Timestamps approximating windows when a given victim was compromised

## Encoding schemes

There are two primary types of encoding used here:
- base32
- polyalphabetic substitution cipher ("base35") 

The base32 encoding scheme is used to encode data that falls outside of the `[a-z0-9-_.]` character set. In that case, the data was prepended with `00` to denote that the following data was base32-encoded. This encoding is implemented in `CryptoHelper.Base64Encode`. I've also implemented it here, in `cryptohelper.CryptoHelper.encode32`, and a decoder in `cryptohelper.CryptoHelper.decode32`.

The other form of encoding present is a substitution cipher, which I'll call "base35" so I don't have to keep typing that. This maps `[a-z0-9-_.]` onto `[a-z0-9]`, using `0` as an escape character and choosing a random mapping for the non-alphanumeric characters. This is implemented in the malware in `CryptoHelper.Base64Decode`. and I've implemented it here in `cryptohelper.CryptoHelper.encode35` and a decoder in `cryptohelper.CryptoHelper.decode35`.

## Three DNS-based message types

All avsvmcloud.com FQDN's include a user ID that can be used to correlate different message types to a specific machine (details below). The region in the FQDN is chosen from the following list using the first byte of the UID (modulo 4) as an index into the list, and so the region is always the same for agiven victim across requests:

- eu-west-1
- us-west-2
- us-east-1
- us-east-2

### Hostname messages

These messages are formatted as follows:

```
+--------+-+------------------------------+
| UID(8) |S| Hostname Fragment (variable) |
+--------+-+------------------------------+

UID ......: An identifier that uniquely identifies a machine. It is MD5(primary MAC address|hostname|MachineGuid), collapsed into 8 bytes via XOR
S ........: A single-byte sequence ID, used to defragment multiple messages
Hostname .: Up to 23 bytes of hostname fragment in a single message
```

In these messages, the UID is masked using a single-byte XOR, the key is prepended to the UID, and the resulting 9 bytes are base-32 encoded into 15 bytes with zero-bits used as padding.

> The decoder tool from CaptanMoss pointed out the presence of these fragments and the ability to correlate them using the UID, but did not use the sequence number to order them.

The sequence number is masked by adding the first byte of the masked, base32-encoded UID modulo 36 and mapping the result onto `[0-9a-z]` (see `CryptoHelper.CreateString`).

The hostname can be encoded one of two ways; if all characters can be represented in the base35 character set, that is used. Otherwise, it is base32-encoded and prepended with `00` to help with reconstruction on the controller.

> The decoder tool from RedDrip decoded hostnames from a single message type, and failed to decode some hostnames altogether (specifically, if an encoded hostname didn't contain a "0")

Note that if a hostname appears truncated, it is probably fragmented. If the DNS dataset is clean enough, you can use the sequence number to piece hostname fragments back together in order.

### Type1 Messages

Another message type is formatted like this:

```
+--------+-------------------+
| UID(8) |flag,timestamp (3) |
+--------+-------------------+

UID .......: An identifier that uniquely identifies a machine. It is MD5(primary MAC address|hostname|MachineGuid), collapsed into 8 bytes via XOR
flag ......: A 4-bit value set to 1 for this message type
Timestamp .: A 20-bit value representing current UTC time on the victim, as number of half-hours since 2010-01-01.
```

In this case, the full message is masked using a single-byte XOR, the key is prepended to the message, and the resulting 12 bytes are base-32 encoded into 20 bytes with zero-bits used as padding.

Prior to applying the single-byte XOR mask, the UID in this message type is also masked using a 2-byte XOR key comprised of the lower two bytes of the timestamp.

### Type2 Messages

The final message format encodes information about started and stopped services on the host, identified by static positions within a list. The format is:

```
+--------+-------------------+------------------------+
| UID(8) | flag,timestamp(3) | Service data (7 bytes) |
+--------+-------------------+------------------------+

UID ..........: An identifier that uniquely identifies a machine. It is MD5(primary MAC address|hostname|MachineGuid), collapsed into 8 bytes via XOR
flag .........: A 4-bit value set to 2 for this message type
Timestamp ....: A 20-bit value representing current UTC time on the victim, as number of half-hours since 2010-01-01.
Service Data .: A string of 52 pairs of bits packed into 7 bytes (zero padded) representing "running" and "stopped" states of services on the victim machine
```

In this case, the full message is masked using a single-byte XOR, the key is prepended to the message, and the resulting 12 bytes are base-32 encoded into 20 bytes with zero-bits used as padding.

Prior to applying the single-byte XOR mask, the UID in this message type is also masked using a 2-byte XOR key comprised of the lower two bytes of the timestamp.

## Using this tool

The encoders and decoders are implemented in `lib.cryptohelper` as well as some of the supporting logic for unmasking and parsing Sunburst CNAMES. Message parsers are included in `lib.message`. A demo is implemented in `dga_parser.py`.

To use:

```
git clone --recurse-submodules https://github.com/klustic/SunBurst_DGA
cd SunBurst_DGA
python3 dga_parser.py --file data/research/sunburst/uniq-hostnames.txt
```

# Acknowledgements 
1. First decoder I saw: https://github.com/RedDrip7/SunBurst_DGA_Decode
2. Improvements over (1) including grouping of hsotname fragments: https://github.com/CaptanMoss/FireeyeSUNBURST-StringDecoder
3. Hostnames from passive DNS (included here as submodule): https://github.com/bambenek/research

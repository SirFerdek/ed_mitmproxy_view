from __future__ import annotations
from typing import TYPE_CHECKING
if TYPE_CHECKING:
  from _typeshed import ReadableBuffer

import base64
import hashlib


class EDCrypt:

  SALT = {
      "289.583.0.0": 0x83b84df79d3c51d,
      "289.925.0.0": 0x744f49943c29e57,
      "291.50.0.0":  0x744f49943c29e57,
  }

  EDDE_PACK_COMMANDS_LUT = [
      0x0001, 0x0804, 0x1001, 0x2001, 0x0002, 0x0805, 0x1002, 0x2002, 0x0003, 0x0806, 0x1003, 0x2003, 0x0004, 0x0807,
      0x1004, 0x2004, 0x0005, 0x0808, 0x1005, 0x2005, 0x0006, 0x0809, 0x1006, 0x2006, 0x0007, 0x080a, 0x1007, 0x2007,
      0x0008, 0x080b, 0x1008, 0x2008, 0x0009, 0x0904, 0x1009, 0x2009, 0x000a, 0x0905, 0x100a, 0x200a, 0x000b, 0x0906,
      0x100b, 0x200b, 0x000c, 0x0907, 0x100c, 0x200c, 0x000d, 0x0908, 0x100d, 0x200d, 0x000e, 0x0909, 0x100e, 0x200e,
      0x000f, 0x090a, 0x100f, 0x200f, 0x0010, 0x090b, 0x1010, 0x2010, 0x0011, 0x0a04, 0x1011, 0x2011, 0x0012, 0x0a05,
      0x1012, 0x2012, 0x0013, 0x0a06, 0x1013, 0x2013, 0x0014, 0x0a07, 0x1014, 0x2014, 0x0015, 0x0a08, 0x1015, 0x2015,
      0x0016, 0x0a09, 0x1016, 0x2016, 0x0017, 0x0a0a, 0x1017, 0x2017, 0x0018, 0x0a0b, 0x1018, 0x2018, 0x0019, 0x0b04,
      0x1019, 0x2019, 0x001a, 0x0b05, 0x101a, 0x201a, 0x001b, 0x0b06, 0x101b, 0x201b, 0x001c, 0x0b07, 0x101c, 0x201c,
      0x001d, 0x0b08, 0x101d, 0x201d, 0x001e, 0x0b09, 0x101e, 0x201e, 0x001f, 0x0b0a, 0x101f, 0x201f, 0x0020, 0x0b0b,
      0x1020, 0x2020, 0x0021, 0x0c04, 0x1021, 0x2021, 0x0022, 0x0c05, 0x1022, 0x2022, 0x0023, 0x0c06, 0x1023, 0x2023,
      0x0024, 0x0c07, 0x1024, 0x2024, 0x0025, 0x0c08, 0x1025, 0x2025, 0x0026, 0x0c09, 0x1026, 0x2026, 0x0027, 0x0c0a,
      0x1027, 0x2027, 0x0028, 0x0c0b, 0x1028, 0x2028, 0x0029, 0x0d04, 0x1029, 0x2029, 0x002a, 0x0d05, 0x102a, 0x202a,
      0x002b, 0x0d06, 0x102b, 0x202b, 0x002c, 0x0d07, 0x102c, 0x202c, 0x002d, 0x0d08, 0x102d, 0x202d, 0x002e, 0x0d09,
      0x102e, 0x202e, 0x002f, 0x0d0a, 0x102f, 0x202f, 0x0030, 0x0d0b, 0x1030, 0x2030, 0x0031, 0x0e04, 0x1031, 0x2031,
      0x0032, 0x0e05, 0x1032, 0x2032, 0x0033, 0x0e06, 0x1033, 0x2033, 0x0034, 0x0e07, 0x1034, 0x2034, 0x0035, 0x0e08,
      0x1035, 0x2035, 0x0036, 0x0e09, 0x1036, 0x2036, 0x0037, 0x0e0a, 0x1037, 0x2037, 0x0038, 0x0e0b, 0x1038, 0x2038,
      0x0039, 0x0f04, 0x1039, 0x2039, 0x003a, 0x0f05, 0x103a, 0x203a, 0x003b, 0x0f06, 0x103b, 0x203b, 0x003c, 0x0f07,
      0x103c, 0x203c, 0x0801, 0x0f08, 0x103d, 0x203d, 0x1001, 0x0f09, 0x103e, 0x203e, 0x1801, 0x0f0a, 0x103f, 0x203f,
      0x2001, 0x0f0b, 0x1040, 0x2040
  ]

  PACKED_MAGIC = bytes("EDDE", 'utf-8')

  def __init__(self, salt: int = None) -> None:
    self.salt = salt

  @staticmethod
  def generate_key(salt: int, nonce: ReadableBuffer) -> bytes:
    salt_str = str(salt) if salt else ""
    salted_nonce = bytes(salt_str, "utf-8") + nonce
    key_bytes = hashlib.sha1(salted_nonce)
    # convert to string to peform .upper()
    key_str = key_bytes.hexdigest().upper()
    return bytes(key_str, 'utf-8')

  @staticmethod
  def xor_encrypt_decrypt(data: ReadableBuffer, key: ReadableBuffer) -> bytearray:
    """
    Performs RC4 encryption/decryption.
    Symmetric usage
    """
    temp_buf = bytearray(range(256))
    magic_var = 0
    for i in range(256):
      c = temp_buf[i]
      magic_var = (magic_var + key[i % len(key)] + c) % 256
      temp_buf[i] = temp_buf[magic_var]
      temp_buf[magic_var] = c
    idx1 = 0
    idx2 = 0
    output = bytearray(len(data))
    for di in range(len(data)):
      idx1 = (di + 1) & 0xFF
      c2 = temp_buf[idx1]
      idx2 = (idx2 + c2) & 0xFF
      temp_buf[idx1] = temp_buf[idx2]
      temp_buf[idx2] = c2
      output[di] = temp_buf[(temp_buf[idx1] + c2) % 256] ^ data[di]
    return output

  def decode_request(self,
                     nonce: ReadableBuffer,
                     query: ReadableBuffer,
                     post_data: ReadableBuffer = None) -> "tuple[bytes, bytes]":
    query_b64dec = base64.b64decode(query)
    post_b64dec = base64.b64decode(post_data) if post_data else bytes()
    key = self.generate_key(self.salt, nonce)
    decoded = self.xor_encrypt_decrypt(query_b64dec + post_b64dec, key)
    decoded_query = bytes(decoded[:len(query_b64dec)])
    decoded_post = bytes(decoded[len(query_b64dec):])
    return (decoded_query, decoded_post)

  def encode_request(self,
                     nonce: ReadableBuffer,
                     query: ReadableBuffer,
                     post_data: ReadableBuffer = None) -> "tuple[bytes, bytes]":
    key = self.generate_key(self.salt, nonce)
    if not post_data:
      post_data = bytes()
    encoded = self.xor_encrypt_decrypt(query + post_data, key)
    encoded_query = bytes(encoded[:len(query)])
    encoded_post = bytes(encoded[len(query):])
    query_b64enc = base64.b64encode(encoded_query)
    post_b64enc = base64.b64encode(encoded_post)
    return (query_b64enc, post_b64enc)

  @staticmethod
  def is_packed_response(data: ReadableBuffer):
    return data[:4] == b'EDDE'

  @staticmethod
  def calc_unpacked_size(data: ReadableBuffer):
    left_shift = 0
    size = 0
    for byte in data[len(EDCrypt.PACKED_MAGIC):]:
      size |= (byte & 0x7f) << left_shift
      if byte < 0x80:
        return size
      left_shift += 7
      if left_shift >= 32:
        raise OverflowError("Left shift exceeded 31 bits")

  @staticmethod
  def get_frame_beginning(data: ReadableBuffer):
    for i, b in enumerate(data[len(EDCrypt.PACKED_MAGIC):]):
      if b < 0x80:
        return i + 1 + len(EDCrypt.PACKED_MAGIC)

  @staticmethod
  def unpack_response(buffer: ReadableBuffer):
    output = bytearray(EDCrypt.calc_unpacked_size(buffer))
    buffer = buffer[EDCrypt.get_frame_beginning(buffer):]
    output_head = 0
    b_ptr = 0
    while b_ptr < len(buffer):
      b = buffer[b_ptr]
      b_ptr += 1
      if (b & 3) == 0:
        # forward copy
        runlength = (b >> 2) + 1
        if (runlength < 0x3D):
          output[output_head:(output_head + runlength)] = buffer[b_ptr:b_ptr + runlength]
          b_ptr += runlength
          output_head += runlength
        else:
          # following 0-4 bytes contain info on runlength
          info_bytes = runlength - 0x3c
          runlength = int.from_bytes(buffer[b_ptr:b_ptr + info_bytes], 'little') + 1
          output[output_head:output_head + runlength] = buffer[b_ptr + info_bytes:b_ptr + info_bytes + runlength]
          b_ptr += info_bytes + runlength
          output_head += runlength
      else:
        # copy fragment from an already unpacked output buffer
        command = EDCrypt.EDDE_PACK_COMMANDS_LUT[b]
        runlength = (command & 0xFF)
        info_bytes = command >> 0x0B
        lookback_offset = command & 0x700
        lookback = lookback_offset + int.from_bytes(buffer[b_ptr:b_ptr + info_bytes], 'little')
        if lookback > output_head:
          # command wants us to go back too much?
          raise ValueError
        while lookback < runlength:
          output[output_head:(output_head + lookback)] = output[output_head - lookback:output_head]
          output_head += lookback
          runlength -= lookback
        output[output_head:(output_head + runlength)] = output[output_head - lookback:output_head - lookback +
                                                               runlength]
        b_ptr += info_bytes
        output_head += runlength
    return bytes(output)

  def decode_response(self, nonce: ReadableBuffer, data: ReadableBuffer):
    ciphertext = base64.b64decode(data)
    key = self.generate_key(self.salt, nonce)
    decoded = self.xor_encrypt_decrypt(ciphertext, key)
    if not self.is_packed_response(decoded):
      raise ValueError("No Magic tag at data beginning")
    unpacked = self.unpack_response(decoded)
    return unpacked

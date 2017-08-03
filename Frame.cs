using System;

namespace Wophi {

  public enum OpCode {
    Continue = 0x00,
    Text     = 0x01,
    Binary   = 0x02,
    Close    = 0x08,
    Ping     = 0x09,
    Pong     = 0x0a
  }

  public struct Frame {
    public bool Fin;
    public bool Masked;
    public byte[] Data;
    public OpCode Opcode;
    public byte[] MaskingKey;

    public bool Rsv1;
    public bool Rsv2;
    public bool Rsv3;
    public bool Complete;
  }

  public static class Framing {

    private static UInt64 GetFrameSize(ref Frame frame) {
      UInt64 size = (UInt64)(2 + (frame.Masked ? 4 : 0) + frame.Data.Length);
      if (frame.Data.Length >= 126 && frame.Data.Length < 63336) size += 2;
      else if (frame.Data.Length >= 65536) size += 8;
      return size;
    }

    public static Frame Parse(byte[] data) {
      UInt64 offset = 0;
      int i, size, count = 0;
      Frame frame = new Frame();

      try {
        // parse first byte (fin, rsv's and opcode)
        frame.Complete = false;
        frame.Fin  = (data[offset] & 0x80) != 0;
        frame.Rsv1 = (data[offset] & 0x40) != 0;
        frame.Rsv1 = (data[offset] & 0x20) != 0;
        frame.Rsv1 = (data[offset] & 0x10) != 0;
        frame.Opcode = (OpCode)(data[offset++] & 0x0f);

        // parse second byte[extended] (masked, payload length)
        frame.Masked = (data[offset] & 0x80) != 0;
        size = (int)(data[offset++] & (~0x80));
        if (size == 127) count = 8;
        else if (size == 126) count = 2;
        if (count > 0) size = 0;
        while (count-- > 0)
          size |= (data[offset++] & 0xff) << (8 * count);
        frame.Data = new byte[size];

        // get mask
        byte[] mask = null;
        if (frame.Masked) {
          mask = new byte[4];
          for (i = 0; i < 4; i++)
            mask[i] = data[offset++];
        }

        // get payload data
        for (i = 0; i < size; i++)
          frame.Data[i] = (byte)(!frame.Masked ? data[(int)(offset) + i]
            : data[(int)(offset) + i] ^ mask[i % 4]);
        frame.Complete = true;

      // incomplete on error
      } catch (Exception ex) {
        frame.Complete = false;
      }

      return frame;
    } 
  }
}
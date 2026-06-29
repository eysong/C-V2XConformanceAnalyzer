import sys
import xml.etree.ElementTree as ET
from bitstream_constructor import BitstreamConstructor

class PDMLParse:
  def __init__(self, filepath):
    self.tree = ET.parse(filepath)
    self.root = self.tree.getroot()
      
  def parse_packet(self, packet):
    fields = []
    for f in packet.findall(".//field"):
      pos = f.get("pos")
      size = f.get("size")
      value = f.get("value")
      if pos and size and value:
        fields.append({
          "name": f.get("name"),
          "pos": int(pos),
          "size": int(size),
          "value": bytes.fromhex(value)
                })
    return sorted(fields, key=lambda x: x["pos"])

  def iterate_packets(self):
    for packet in self.root.findall(".//packet"):
      yield self.parse_packet(packet)


class Analyze:
  def __init__(self, fields):
    self.fields = fields
  def validate(self):
    term = 0
    for f in self.fields:
      if f["pos"] != term:
        print("gap at", f)
      term = f["pos"] + f["size"]

  def get_segments(self):
    return [(f["pos"], f["value"]) for f in self.fields]




parser = PDMLParse(sys.argv[1]) #second parameter to run?

for fields in parser.iterate_packets():
  Analyze(fields).validate()
  segments = Analyze(fields).get_segments()

  raw_bytes = BitstreamConstructor(segments).bytes()
  bitstream = BitstreamConstructor(segments).bits()

  print("Raw bytes:", raw_bytes.hex())
  print("Bitstream:", bitstream)

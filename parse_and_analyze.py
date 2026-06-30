class PDMLParse:
  def __init__(self, filepath):
    self.tree = ET.parse(filepath)
    self.root = self.tree.getroot()
      
  def parse_packet(self, packet):
    fields = [] #set up a list to store all fields, each element is a dictionary to store attributes
    for f in packet.findall(".//field"): #for each field in THIS packet
      pos = f.get("pos")
      size = f.get("size")

      #validate value
      value = f.get("value")
      if value is None or any(c not in "0123456789abcdefABCDEF" for c in value):
        continue

      value = value.replace("0x","").replace(":","").replace("-","").strip()

      if len(value) % 2 == 1:
        value = "0" + value
      ######
      
      if pos and size and value:
        fields.append({
          "name": f.get("name"),
          "pos": int(pos),
          "size": int(size),
          "value": bytes.fromhex(value)
          })
    return sorted(fields, key=lambda x: x["pos"])#list of fields sorted by position

  def iterate_packets(self):
    for packet in self.root.findall(".//packet"): #for each packet in the pdml
      yield self.parse_packet(packet)


class Analyze:
  def __init__(self, fields):
    self.fields = fields
  def validate(self): #ensure that there are no gaps in the bytestring
    term = 0
    for f in self.fields:
      if f["pos"] != term:
        print("gap at", f)
      term = f["pos"] + f["size"]

  def get_segments(self):
    return [(f["pos"], f["value"]) for f in self.fields] #return a tuple w/ position and value for each field

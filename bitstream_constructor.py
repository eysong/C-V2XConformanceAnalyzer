class BitstreamConstructor:
    def __init__(self, segment_list):
      self.segments = segment_list

    def bytes(self):
      return b"".join(seg[1] for seg in self.segments)

    def bits(self):
      return "".join(f"{byte:08b}" for byte in raw)

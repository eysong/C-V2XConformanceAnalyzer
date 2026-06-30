import sys
import xml.etree.ElementTree as ET
from bitstream_constructor import BitstreamConstructor
from parse_and_analyze import PDMLParse, Analyze



parser = PDMLParse(sys.argv[1]) #second parameter when running

for fields in parser.iterate_packets():
  analyzer = Analyze(fields)
  analyzer.validate()
  segments = analyzer.get_segments()

  constructor = BitstreamConstructor(segments)
  raw_bytes = constructor.bytes()
  bitstream = constructor.bits()

  print("Raw bytes:", raw_bytes.hex())
  print("Bitstream:", bitstream)

# Test Files
Vendor PDML files are not distributed within this repository.

To use this tool:
1. Export packets from Wireshark (v 4.6.6) as PDML.
2. Place the PDML file in this directory.
3. Run from the repository root:
```shell
python src/cv2x-conform-analyzer.py test_files/<filename>.pdml
```

import pandas as pd

# EVAL METHODS [val1, val2]:
# 0 = compare with min, max [min, max]
# 1 = octet count [cnt, 00]
# 2 = bit string [len, 00]
# 3 = boolean [00, 00]
# 4 = hashalg list [00, 00]
# 5 = IA5 string [minlen, maxlen]
# 6 = UTF8 string [minlen, maxlen]
# 7 = signer [00, 00]
# 8 = sequence-of item count [minitems, maxitems]

ieee16093_wsmp_ref = [  # col[0] = field name, col[1] = parent name, col[2] = length, col[3] = eval method, col[4] = ref value 1, col[5] = ref value 2, col[6] = mandatory?
    ["wsmp.version", "wsmp", 1, 0, 3, 3, True],
    ["wsmp.subtype", "wsmp", 1, 0, 0, 0, True], #parent forced to "wsmp" in main program
    ["wsmp.option", "wsmp", 1, 3, 00, 00, True],
    ["wsmp.n_ext", "wsmp", 1, 0, 0, 5, False],
    ["wsmp.txpower", "wsmp", 1, 0, -128, 127, False],

    # WAVE IE extension fields: defined by IEEE 1609.3 but NOT individually decoded by the Wireshark WSMP dissector (bundled in wave_ie TLVs).
    ["wsmp.channel", "wsmp", 1, 1, 1, 00, False],
    ["wsmp.rate", "wsmp", 1, 0, 2, 127, False],
    ["wsmp.load", "wsmp", 1, 1, 1, 00, False],
    ["wsmp.confidence", "wsmp", 1, 0, 0, 7, False],
    ###

    ["wsmp.tpid", "wsmp", 1, 0, 0, 5, True],
    ["wsmp.psid", "wsmp", 4, 0, 0, 4294967295, True],
    ["wsmp.length", "wsmp", 2, 0, 0, 16383, True],
    ["wsmp.wave_ie", "wsmp", 1, 0, 0, 127, False],   
    ["wsmp.wave_ie_len",  "wsmp", 1, 0, 0, 255, False],   
    ["wsmp.wave_ie_data", "wsmp", 1, 0, 0, 255, False],   
]
ieee16093_wsmp_refdf = pd.DataFrame(ieee16093_wsmp_ref, columns = ["field", "parent", "length", "eval method", "val1", "val2", "mandatory"])

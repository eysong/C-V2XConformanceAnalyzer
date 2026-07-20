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

ieee16092_spdu_ref = [  # col[0]=field, col[1]=parent, col[2]=length, col[3]=eval method, col[4]=val1, col[5]=val2, col[6]=mandatory
    # ===== Ieee1609Dot2Data (outermost SPDU) =====
    ["ieee1609dot2.protocolVersion", "ieee1609dot2.Ieee1609Dot2Data_element", 1, 0, 0, 255, True], 
    ["ieee1609dot2.content", "ieee1609dot2.Ieee1609Dot2Data_element", 1, 0, 0, 128, False],
    ["ieee1609dot2.unsecuredData",   "ieee1609dot2.content", 662, 1, 662, 00, False],  

    # ===== SignedData =====
    ["ieee1609dot2.hashId",    "ieee1609dot2.signedData_element", 1, 4, 00, 00, True],  
    ["ieee1609dot2.signer",    "ieee1609dot2.signedData_element", 1, 7, 00, 00, True],   
    ["ieee1609dot2.digest",    "ieee1609dot2.signer", 8, 1, 8, 00, False],               

    # ----- tbsData > headerInfo -----
    ["ieee1609dot2.hiPsid",               "ieee1609dot2.headerInfo_element", 3, 0, 0, 4294967295, True], 
    ["ieee1609dot2.generationTime",       "ieee1609dot2.headerInfo_element", 8, 1, 8, 00, False],         
    ["ieee1609dot2.expiryTime",           "ieee1609dot2.headerInfo_element", 8, 1, 8, 00, False],          
    ["ieee1609dot2.p2pcdLearningRequest", "ieee1609dot2.headerInfo_element", 3, 1, 3, 00, False],          

    # ----- headerInfo > generationLocation (ThreeDLocation) -----
    ["ieee1609dot2.latitude",  "ieee1609dot2.generationLocation_element", 4, 0, -900000000,  900000001,  False],
    ["ieee1609dot2.longitude", "ieee1609dot2.generationLocation_element", 4, 0, -1799999999, 1800000001, False],
    ["ieee1609dot2.elevation", "ieee1609dot2.generationLocation_element", 2, 0, 0, 61439, False],

    # ===== signature > ecdsaNistP256Signature =====
    ["ieee1609dot2.sSig",          "ieee1609dot2.ecdsaNistP256Signature_element", 32, 1, 32, 00, True],
    ["ieee1609dot2.x_only",        "ieee1609dot2.rSig", 32, 1, 32, 00, False],
    ["ieee1609dot2.compressed_y_0","ieee1609dot2.rSig", 32, 1, 32, 00, False],
    ["ieee1609dot2.compressed_y_1","ieee1609dot2.rSig", 32, 1, 32, 00, False],

    # ===== Certificate =====
    ["ieee1609dot2.version", "ieee1609dot2.Certificate_element", 1, 0, 0, 255, True],  
    ["ieee1609dot2.type",    "ieee1609dot2.Certificate_element", 1, 0, 0, 1,   True], 

    # ----- issuer -----
    ["ieee1609dot2.sha256AndDigest", "ieee1609dot2.issuer", 8, 1, 8, 00, False],  

    # ----- toBeSigned (ToBeSignedCertificate) -----
    ["ieee1609dot2.cracaId",             "ieee1609dot2.toBeSigned_element", 3, 1, 3, 00, True],   
    ["ieee1609dot2.crlSeries",           "ieee1609dot2.toBeSigned_element", 2, 0, 0, 65535, True],

    # ----- certificateId (CHOICE) -----
    ["ieee1609dot2.name",     "ieee1609dot2.certificateId", 7, 6, 1, 63, False],   
    ["ieee1609dot2.binaryId", "ieee1609dot2.certificateId", 8, 1, 8, 00, False],   
    ["ieee1609dot2.none",     "ieee1609dot2.certificateId", 1, 3, 00, 00, False],  

    # ----- certificateId > linkageData -----
    ["ieee1609dot2.iCert",         "ieee1609dot2.linkageData_element", 2, 0, 0, 65535, False],  
    ["ieee1609dot2.linkage_value", "ieee1609dot2.linkageData_element", 9, 1, 9, 00, False],    
    ["ieee1609dot2.jValue",        "ieee1609dot2.group_linkage_value_element", 4, 1, 4, 00, False],  
    ["ieee1609dot2.value",         "ieee1609dot2.group_linkage_value_element", 9, 1, 9, 00, False],  

    # ----- validityPeriod -----
    ["ieee1609dot2.start",    "ieee1609dot2.validityPeriod_element", 4, 1, 4, 00, True],   
    ["ieee1609dot2.hours",    "ieee1609dot2.duration", 2, 0, 0, 65535, False],
    ["ieee1609dot2.minutes",  "ieee1609dot2.duration", 2, 0, 0, 65535, False],
    ["ieee1609dot2.years",    "ieee1609dot2.duration", 2, 0, 0, 65535, False],

    # ----- region -----
    ["ieee1609dot2.countryOnly", "ieee1609dot2.IdentifiedRegion", 2, 0, 0, 65535, False],  

    # ----- appPermissions > PsidSsp -----
    ["ieee1609dot2.psPsid", "ieee1609dot2.PsidSsp_element", 4, 0, 0, 4294967295, False],  
    ["ieee1609dot2.opaque", "ieee1609dot2.ssp", 4, 1, 4, 00, False],                       

    # ----- verifyKeyIndicator > reconstructionValue -----
    ["ieee1609dot2.compressed_y_0", "ieee1609dot2.reconstructionValue", 32, 1, 32, 00, False],
    ["ieee1609dot2.compressed_y_1", "ieee1609dot2.reconstructionValue", 32, 1, 32, 00, False],

    # ===== nested Ieee1609Dot2Data (inside payload > data) =====
    ["ieee1609dot2.protocolVersion", "ieee1609dot2.data_element", 1, 0, 0, 255, False], 
]
ieee16092_spdu_refdf = pd.DataFrame(ieee16092_spdu_ref,
    columns=["field", "parent", "length", "eval method", "val1", "val2", "mandatory"])

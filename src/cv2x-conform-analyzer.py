import re
import sys
import time
import pandas as pd
from lxml import etree

pd.set_option('display.max_columns', None)
pd.set_option('display.max_rows', None)
pd.set_option('display.max_colwidth', None)
pd.set_option('display.width', 1000)

from j2735_ref_tables_new import saej2735_bsm_refdf, saej2735_spat_refdf, saej2735_rsa_refdf, saej2735_tim_refdf, saej2735_map_refdf
from ieee16093_ref_tables import ieee16093_wsmp_refdf
from ieee16092_ref_tables import ieee16092_spdu_refdf

# GLOBAL ACCESSED DATAFRAMES/VARIABLES
faildf = pd.DataFrame(columns=["field", "parent", "message", "length", "value", "occurrences", "fail description"])   # DataFrame where each row is the_files of analysis for a FAILED field.
iop_file = True
iop_file_fail_desc = ""

# ------- DEFINE QUANTITATIVE EVALUATION METHODS -------
# Eval Method 0: compare with min, max
def compare_min_max(row, fieldval):
    minval = row.get('val1').values[0]
    maxval = row.get('val2').values[0]
    
    if((minval <= fieldval) and (fieldval <= maxval)):
        return True
    else:
        return False

# Eval Method 1: octet count
def octet_count(row, fieldlen):
    targetval = row.get('val1').values[0]
    if((fieldlen > 0) and (fieldlen <= targetval)):
        return True
    else:
        return False

# Eval Method 2: bit string
def bit_string(row, field, iop_fail_desc):
    target_bitlen = row.get('val1').values[0]
    try:
        field_bitlen = int(re.findall(r"bit length (\d+)", field.attrib.get('showname'))[0])
    except IndexError:
        iop_fail_desc = iop_fail_desc + "Incorrect format for bit string. "
        return False
    if (field_bitlen <= target_bitlen):
        return True
    else:
        return False

# Eval Method 3: boolean
def boolean_check(fieldval):
    if ((fieldval == 0) or (fieldval == 1)):
        return True
    else:
        return False

# Eval Method 4: hashalg list
def hashalg_list(field):
    hashname = re.findall(r"HashAlgorithm: (\w+)", field.attrib.get('showname'))[0]
    if ((hashname == "sha256") or (hashname == "sha384") or (hashname == "sm3")):
        return True
    else:
        return False

# Eval Method 5: IA5 string
def ia5str(row, fieldval, fieldlen):
    minlength = row.get('val1').values[0]
    maxlength = row.get('val2').values[0]

    if fieldlen < minlength or fieldlen > maxlength:
        return False
    
    try:
        fieldval.encode("ascii")
    except UnicodeEncodeError:
        return False

    return True

# Eval Method 6: UTF8 string
def utf8str(row, fieldval, fieldlen):
    minlength = row.get('val1').values[0]
    maxlength = row.get('val2').values[0]

    # 0,0 means no length restriction
    if not (minlength == 0 and maxlength == 0):
        if fieldlen < minlength or fieldlen > maxlength:
            return False

    try:
        fieldval.encode("UTF-8")
    except UnicodeEncodeError:
        return False

    return True

# Eval Method 7: signer
def signer(field):
    signername = re.findall(r"signer: (\w+)", field.attrib.get('showname'))[0]
    if ((signername == "digest") or (signername == "certificate")):
        return True
    else:
        return False

def normalize_field_name(fieldname):
    if fieldname is None:
        return None

    # Remove Wireshark version prefixes
    fieldname = fieldname.replace("j2735_2016.", "j2735.")

    # Remove ASN.1 suffixes
    fieldname = re.sub(r"_(\d+)$", "", fieldname)

    # Remove structural ASN.1 wrappers
    ignore_suffixes = ["_element", "_value",]

    for suffix in ignore_suffixes:
        if fieldname.endswith(suffix):
            fieldname = fieldname[:-len(suffix)]

    fieldname = apply_alias(fieldname)
    return fieldname


def normalize_parent_name(parentname):
    if parentname is None:
        return None

    parentname = parentname.replace("j2735_2016.","j2735.")

    parentname = re.sub(r"_(\d+)$","",parentname)

    parentname = apply_alias(parentname)
    return parentname

def apply_alias(name):
    # J2735 alias dictionary (for parent and field)
    aliases = {
        #standard field name: alias
        "j2735.revision":"j2735.msgIssueRevision",
        "j2735.MapData_element":"j2735.MapData",
    }
    return aliases.get(name, name)

# ------- ANALYZE PDML METHOD: Given a tree (parsed XML file), will iterate through every field of each relevant message to determine interoperability and compliance to standards. -------
def analyze(tree):
    global iop_file
    global iop_file_fail_desc
    iop_file = True
    iop_file_fail_desc = ""
    faildf.drop(faildf.index, inplace=True)

    # DETERMINE PACKET AND PROTOCOL
    for packet in tree.getroot():
        iop_packet = True
        for proto in packet.iter('proto'): #CHANGED from proto in packet: to allow for wider compatability
            iop_proto = True
            refdf = None
            messagename = None

            # DETERMINE PROTOCOL AND MESSAGE TYPE, SET CORRESPONDING REFERENCE DATAFRAME
            if ("j2735" in proto.attrib.get('name')):   # SAE J2735
                
                messageId = None
                for f in proto.iter("field"):
                    name = f.attrib.get("name", "")
                    if name.endswith(".messageId"):
                        messageId = f
                        break
                    
                if (messageId != None):
                    messagename = "SAE J2735: " + re.findall(r"messageId: (.+)", messageId.attrib.get('showname'))[0]
                    codenum = int(messageId.attrib.get('show'))
                    match codenum:
                        case 20:    # BSM
                            refdf = saej2735_bsm_refdf
                        case 27:    # RSA
                            refdf = saej2735_rsa_refdf
                        case 19:    # SPaT
                            refdf = saej2735_spat_refdf
                        case 31:    # TIM
                            refdf = saej2735_tim_refdf
                        case 18:    # MAP
                            refdf = saej2735_map_refdf
                        case _:
                            iop_file = False
                            iop_file_fail_desc += ("Invalid messageId: " + str(messageId.attrib.get('show'))+ "\n")
                            
            elif ("16093" in proto.attrib.get('name')): # IEEE 1609.3
                messagename = "IEEE 1609.3: WAVE Short Message Protocol"
                refdf = ieee16093_wsmp_refdf
                
            elif ("16092" in proto.attrib.get('name')): # IEEE 1609.2
                messagename = "IEEE 1609.2: WAVE Security Signed Data"
                refdf = ieee16092_spdu_refdf
                
            else:
                continue

            if (messagename is not None):
                print(messagename)
                print("--------------------------------------------")
                

            # SET MESSAGE REFERENCE TABLE VARIABLES FOR SEQUENCE CHECKING
            if ((refdf is not None) and (not refdf.empty)):
                # Build the ordered list of mandatory fields from the reference table.
                # This preserves the standard-defined sequence so incoming PDML fields
                    # can be checked to ensure mandatory elements appear in the correct order.
                mandatory_sequence = (
                    refdf[refdf["mandatory"] == True]
                    [["field", "parent"]]
                    .reset_index(drop=True)
                )

                sequence_tracker = {}
                mandatory_seen = {}

                # ------- IoP ANALYSIS -------
                ignored_fields = [
                        "j2735.MessageFrame",
                        "j2735.value",
                        "j2735.BasicSafetyMessage",
                        "j2735.MapData",
                        "j2735.coreData",
                        "j2735.partII",
                        "j2735.PartIIcontent",
                        "j2735.partII_Value",
                    ]
                for field in proto.iter('field'):  # iteratively move through fields - CHANGED from proto.iter() to proto.iter('field')
                    iop_tag = True
                    iop_length = True
                    iop_value = True
                    iop_sequence = True
                    iop_field = True
                    iop_fail_desc = ""

                    fieldname = normalize_field_name(field.attrib.get('name'))
                    parentname = parentname = normalize_parent_name(field.getparent().attrib.get("name"))


                    if fieldname in ignored_fields:
                        continue

                    if (fieldname == "per.optional_field_bit"): # optional field handler
                        if ("True" in str(field.attrib.get('showname'))):
                            fieldname = "j2735." + re.findall(r"\(([^ ]+?) ", field.attrib.get('showname'))[0]
                        else:
                            continue

                    row = refdf.loc[(refdf['field'] == fieldname) & (refdf['parent'] == parentname)]    # get row based on field name and parent name

                    if row.empty:
                        continue
                    
                    if ((len(row.index) != 1)): # only 1 entry per unique pair of field name and parent name
                        print("NO MATCH")
                        print(" Field :", fieldname)
                        print(" Parent:", parentname)
                        if ((len(row.index) != 0) and not row.empty):
                            iop_tag = False
                            iop_fail_desc = iop_fail_desc + "Invalid/Repeated tag. "
                        # *IF TRACKING SKIPPED FIELDS:
                        # if (row.empty):
                        #     skipdf.loc[len(skipdf.index)] = [fieldname, parentname, messagename]
                        
                    else:
                        # SEQUENCE CHECKING
                        fieldmand_ref = row.get("mandatory").values[0]

                        if fieldmand_ref:
                            parent_element = field.getparent()

                            key = id(parent_element)

                            if key not in mandatory_seen:
                                mandatory_seen[key] = {
                                    "element": parent_element,
                                    "fields": []
                                }

                            mandatory_seen[key]["fields"].append(fieldname)
                            
                            if key not in sequence_tracker:
                                sequence_tracker[key]=0
                            current_index = sequence_tracker[key]

                            parent_sequence = mandatory_sequence[mandatory_sequence["parent"] == parentname].reset_index(drop=True)

                            if current_index < len(parent_sequence):
                                expected = parent_sequence.iloc[current_index]
                                if(fieldname == expected["field"]):
                                    sequence_tracker[key] +=1
                                else:
                                    matches = parent_sequence[parent_sequence["field"] == fieldname]

                                    if not matches.empty:
                                        sequence_tracker[key] = (matches.index[0]+1)
                                    else:
                                        iop_sequence = False
                                        iop_fail_desc += (f"Unexpected sequence position: " f"{fieldname} in {parentname}.")
                        

                        # LENGTH EVALUATION OF FIELD
                        fieldlen = int(field.attrib.get('size'), 10)
                        eval_method = row.get("eval method").values[0]

                        # IA5 and UTF8 strings validate their own lengths
                        if eval_method not in (5, 6):
                            if fieldlen < 1 or fieldlen > row.get("length").values[0]:
                                iop_length = False
                                iop_fail_desc += (f"Incorrect length: {fieldlen} " f"should be {row.get('length').values[0]}. ")
                                
                        # CONVERT STRING (FROM DATAFILE) TO INT VALUES
                        try:
                            fieldval = int(field.attrib.get('show'), 10)
                        except (ValueError, TypeError):
                            try:
                                fieldval = int(field.attrib.get('value'), 16)
                            except (ValueError, TypeError):
                                iop_value = False
                                iop_fail_desc += "Unable to parse value. "
                                fieldval = None

                        # QUANTITATIVE (VALUE) EVALUATION OF FIELD
                        if fieldval is not None:
                            match eval_method:  # determine how the field should be evaluated based on standard
                                case 0:
                                    iop_value = compare_min_max(row, fieldval)
                                case 1:
                                    iop_value = octet_count(row, fieldlen)
                                case 2:
                                    if (not (re.findall(r"bit length", str(field.attrib.get('showname'))))):
                                        continue
                                    else:
                                        iop_value = bit_string(row, field, iop_fail_desc)
                                case 3:
                                    iop_value = boolean_check(fieldval)
                                case 4:
                                    fieldval = re.findall(r"HashAlgorithm: (\w+)", str(field.attrib.get('showname')))[0]
                                    iop_value = hashalg_list(field)
                                case 5:
                                    fieldval = re.findall(r": (.+)", str(field.attrib.get('showname')))[0]
                                    iop_value = ia5str(row, fieldval, fieldlen)
                                case 6:
                                    fieldval = re.findall(r": (.+)", str(field.attrib.get('showname')))[0]
                                    iop_value = utf8str(row, fieldval, fieldlen)
                                case 7:
                                    fieldval = re.findall(r"signer: (\w+)", str(field.attrib.get('showname')))[0]
                                    iop_value = signer(field)
                                case _:
                                    iop_value = False
                                    iop_fail_desc = iop_fail_desc + "Invalid evaluation method. "
                                    continue
                            if (not iop_value):   # field failed evaluation
                                iop_fail_desc = iop_fail_desc + "Value out of range/invalid. "

                        # SAVE FIELD RESULTS
                        if (not iop_tag or not iop_length or not iop_value or not iop_sequence):    # at least one T/L/V metric failed
                            iop_field = False
                            iop_proto = False
                            iop_packet = False
                            iop_file = False
                            row_fail = faildf.loc[(faildf['field'] == fieldname) & (faildf['parent'] == parentname) & (faildf['message'] == messagename)]
                            if len(row_fail) != 0:
                                idx = row_fail.index[-1]
                                existing = faildf.at[idx, "fail description"]

                                if iop_fail_desc.rstrip() not in existing:
                                    faildf.at[idx, "fail description"] = (
                                        existing + " | " + iop_fail_desc.rstrip()
                                    )

                                faildf.at[idx, "occurrences"] += 1

                            else:
                                faildf.loc[len(faildf.index)] = [
                                    fieldname,
                                    parentname,
                                    messagename,
                                    fieldlen,
                                    fieldval,
                                    1,
                                    iop_fail_desc.rstrip()
                                ]
                                
                        # *IF TRACKING ALL ACCESSED FIELDS:
                        # row_assess = assessdf.loc[(assessdf['field'] == fieldname) & (assessdf['parent'] == parentname) & (assessdf['message'] == messagename) & (assessdf['compliant'] == iop_field)]
                        # if (len(row_assess) != 0):
                        #     assessdf.loc[len(assessdf.index)] = [fieldname, parentname, messagename, fieldlen, fieldval, iop_field, row_assess.tail(1).get('occurrences').values[0] + 1]
                        # else:
                        #     assessdf.loc[len(assessdf.index)] = [fieldname, parentname, messagename, fieldlen, fieldval, iop_field, 1]

                        # ------- PRINT FIELD RESULTS -------
                        print("Tag:", fieldname, ">", iop_tag)
                        print("Length:", fieldlen, ">", iop_length)
                        print("Value:", fieldval, ">", iop_value)
                        print("Sequence:", iop_sequence)
                        print("*Field Compliant:", iop_field, "\n")

                # CHECK FOR MISSING MANDATORY FIELDS
                for parent_id, data in mandatory_seen.items():

                    parent_instance = data["element"]
                    seen = data["fields"]

                    parent_type = normalize_parent_name(
                        parent_instance.attrib.get("name")
                    )

                    expected_fields = set(
                        mandatory_sequence[
                            mandatory_sequence["parent"] == parent_type
                        ]["field"]
                    )

                    seen_fields = set(seen)

                    missing_fields = expected_fields - seen_fields

                    for missing in missing_fields:
                        iop_proto = False
                        iop_packet = False
                        iop_file = False

                        faildf.loc[len(faildf.index)] = [
                            missing,
                            parent_type,
                            messagename,
                            0,
                            "MISSING",
                            1,
                            "Mandatory field missing."
                        ]
                            
                print("**Protocol/Message Interoperable:", iop_proto, "\n")

        if (refdf is not None):
            print("***Packet Interoperable:", iop_packet, "\n")

        if (iop_file_fail_desc != ""):
            print(iop_file_fail_desc)

    # PRINT OVERALL RESULTS
    print("-------------------------------------------------------------------------------------------------------------------\n")
    if (iop_file):
        print("File Interoperability: PASS")
    else:
        print("File Interoperability: FAIL")
        print(faildf)
    print("\n-------------------------------------------------------------------------------------------------------------------\n")

# MAIN PROGRAM
def main():
   try:
       in_file = sys.argv[1]
   except IndexError:
       print("Error: Specify a pdml file.")
       sys.exit(1)
   start_time = time.time()
   print("Parsing...")
   tree = etree.parse(in_file)
   print("Analyzing...")
   analyze(tree)
   end_time = time.time()
   print("\n*** Execution time:", (end_time - start_time)/60 , "minutes ***")

if __name__ == "__main__":
    main()

import argparse
import re
import sys
import time
from dataclasses import dataclass, field as dc_field
from enum import Enum
from typing import Optional, Any, List
from lxml import etree
from dataclasses import dataclass
import pandas as pd
from collections import defaultdict

from j2735_ref_tables import (saej2735_bsm_refdf, saej2735_spat_refdf, saej2735_rsa_refdf,
    saej2735_tim_refdf, saej2735_map_refdf,)
from ieee16092_ref_tables import ieee16092_spdu_refdf
from ieee16093_ref_tables import ieee16093_wsmp_refdf

# STANDARD IDENTIFICATION
class Standard(Enum):
    J2735 = "SAE J2735"
    IEEE16092 = "IEEE 1609.2"
    IEEE16093 = "IEEE 1609.3 (WSMP)"
    UNKNOWN = "unknown"

# J2735 DSRC message IDs
J2735_MESSAGE_IDS = {
    18: "MAP",
    19: "SPAT",
    20: "BSM",
    27: "RSA",
    31: "TIM",
}

# UNIFIED NORMALIZER
IGNORE_SUFFIXES = ["_element", "_value"]

J2735_ALIASES = {
    "j2735.revision": "j2735.msgIssueRevision",
    "j2735.MapData_element": "j2735.MapData",
    "j2735.transmisson": "j2735.transmission",
    "j2735.speed_element": "j2735.TransmissionAndSpeed_element",
}

IEEE16092_CANON = "ieee1609dot2."
IEEE16092_PREFIXES = ("ieee1609dot2.", "sec.", "its.sec.", "16092.")
IEEE16092_ALIASES = {}

WSMP_ALIASES = {
    "wsmp.version_v3": "wsmp.version",
    "wsmp.no_elements": "wsmp.n_ext",
    "wsmp.len.det": "wsmp.length",
    "wsmp.N_header_opt_ind": "wsmp.option",
    "wsmp.subtype_vX": "wsmp.subtype"
}

# WSMP WAVE IE fields - not value-validatable, skip evaluation.
WSMP_WAVE_IE_IGNORE = {
    "wsmp.wave_ie",
    "wsmp.wave_ie_data",
    "wsmp.wave_ie_len",
}


J2735_TABLES = {
    "BSM": saej2735_bsm_refdf,
    "SPAT": saej2735_spat_refdf,
    "MAP": saej2735_map_refdf,
    "TIM": saej2735_tim_refdf,
    "RSA": saej2735_rsa_refdf,
}

# UNVERIFIED FIELDS - 1609.2 bounded-integer ranges inferred without the ASN.1
UNVERIFIED_FIELDS = {
    ("ieee1609dot2.generationLocation_element", "ieee1609dot2.elevation"),
    ("ieee1609dot2.Ieee1609Dot2Data_element", "ieee1609dot2.content"),
    ("ieee1609dot2.toBeSigned_element", "ieee1609dot2.crlSeries"),
    ("ieee1609dot2.linkageData_element", "ieee1609dot2.iCert"),
    ("ieee1609dot2.IdentifiedRegion", "ieee1609dot2.countryOnly"),
    ("ieee1609dot2.duration", "ieee1609dot2.hours"),
    ("ieee1609dot2.duration", "ieee1609dot2.minutes"),
    ("ieee1609dot2.duration", "ieee1609dot2.years"),
}

# RSA is unvalidated (no RSA traffic in test data)
UNVERIFIED_MESSAGE_TYPES = {"RSA"}

# Fields that are ASN.1 NULL — presence alone is valid, no value to check
NULL_FIELDS = {
    ("ieee1609dot2.certificateId", "ieee1609dot2.none"),
}

# VERDICTS
class Verdict(Enum):
    PASS = "pass"
    FAIL = "fail"
    UNMAPPED = "unmapped"     # DATA field with no matching rule
    AMBIGUOUS = "ambiguous"   # matched >1 rule
    UNPARSEABLE = "unparseable"

def _strip_instance_suffix(name):
    if name is None:
        return None
    name = re.sub(r"_(\d+)(_element)$", r"\2", name)
    name = re.sub(r"_(\d+)$", "", name)
    return name

def _collapse_node_xy(name):
    if name is None:
        return None
    return re.sub(r"node_XY\d", "node_XY", name)

def _strip_ignore_suffixes(name):
    for suffix in IGNORE_SUFFIXES:
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name

def normalize(name, standard, is_parent=False):
    #Normalize a field or parent name according to its standard
    #is_parent: parents KEEP _element 
    #           fields have _element stripped.
    
    if name is None:
        return None
    if standard == Standard.J2735:
        name = _strip_instance_suffix(name)
        name = _collapse_node_xy(name)
        if not is_parent:
            name = _strip_ignore_suffixes(name)
        return J2735_ALIASES.get(name, name)
    if standard == Standard.IEEE16092:
        for alt in IEEE16092_PREFIXES:
            if name.startswith(alt):
                name = IEEE16092_CANON + name[len(alt):]
                break
        name = _strip_instance_suffix(name)
        if not is_parent:
            name = _strip_ignore_suffixes(name)
        return IEEE16092_ALIASES.get(name, name)
    if standard == Standard.IEEE16093:
        name = name.replace("ieee1609dot3.", "wsmp.")
        name = _strip_instance_suffix(name)
        # WSMP is flat
        return WSMP_ALIASES.get(name, name)
    return name

# FIELD CLASSIFICATION 
class Category(Enum):
    DATA = "data"            # a real leaf to validate
    CONTAINER = "container"  # structural node (skip)
    BITSTRING = "bitstring"  # expanded bit of a bitstring parent (skip)
    ENCODING = "encoding"    # framing artifact (skip)
    RESERVED = "reserved"    # doNotUse (skip)

# J2735 bitstring bit children 
BITSTRING_BIT_RE = re.compile(
    r"\.(?:BrakeAppliedStatus|VehicleEventFlags|LaneSharing|HeadingSlice|"
    r"IntersectionStatusObject|GNSSstatus|AllowedManeuvers|LaneDirection|"
    r"LaneAttributes\.\w+)\."
)
# J2735 bitstring PARENT fields (validate w/ method 2)
BITSTRING_PARENT_NAMES = {
    "j2735.wheelBrakes", "j2735.events", "j2735.sharedWith",
    "j2735.directionalUse", "j2735.direction", "j2735.viewAngle",
    "j2735.status", "j2735.currGNSSstatus", "j2735.maneuvers",
    "j2735.maneuver", "j2735.vehicle", "j2735.crosswalk", "j2735.bikeLane",
    "j2735.sidewalk", "j2735.median", "j2735.striping",
    "j2735.trackedVehicle", "j2735.parking",
}
# 1609.2 CHOICE selectors (dedicated eval methods)
CHOICE_VALIDATE = {
    "ieee1609dot2.signer",   # method 7
}
RESERVED_RE = re.compile(r"\.(?:doNotUse|reserved)\d*$", re.IGNORECASE)
ENCODING_PREFIXES = ("per.", "oer.", "ber.")
# wrappers to ignore per standard
ALWAYS_IGNORE = {
    "j2735.MessageFrame", "j2735.value", "j2735.messageId",
    "ieee1609dot2.messageId",
}

def is_leaf(field_el):
    return field_el.find("field") is None

def children_are_all_bits(field_el):
    children = field_el.findall("field")
    if not children:
        return False
    return all(BITSTRING_BIT_RE.search(c.attrib.get("name", "") or "")
               for c in children)

def classify(fieldname, field_el, standard):
    #classify a normalized fieldname into DATA, CONTAINER, BITSTRING, ENCODING, RESERVED
    if fieldname in WSMP_WAVE_IE_IGNORE:
        return Category.CONTAINER
    if fieldname is None or fieldname == "":
        return Category.CONTAINER
    if fieldname.startswith(ENCODING_PREFIXES):
        return Category.ENCODING
    if BITSTRING_BIT_RE.search(fieldname):
        return Category.BITSTRING
    if RESERVED_RE.search(fieldname):
        return Category.RESERVED
    if fieldname in ALWAYS_IGNORE:
        return Category.CONTAINER
    
    # Bitstring parents (J2735) = data
    if fieldname in BITSTRING_PARENT_NAMES or children_are_all_bits(field_el):
        return Category.DATA
    # explicitly validate (1609.2 signer)
    if fieldname in CHOICE_VALIDATE:
        return Category.DATA
    # Structural node with children = container
    if not is_leaf(field_el):
        return Category.CONTAINER
    return Category.DATA

# FIELD RECORD
@dataclass
class FieldRecord:
    standard: Standard
    raw_name: str
    canonical_name: Optional[str]
    canonical_parent: Optional[str]
    size: Optional[int]
    show: Optional[str]
    showname: Optional[str]
    category: Category
    element: Any = dc_field(repr=False, default=None)


def _size(field_el):
    s = field_el.attrib.get("size")
    return int(s) if s and s.isdigit() else None

def make_record(field_el, standard):
    raw = field_el.attrib.get("name", "")
    canon = normalize(raw, standard, is_parent=False)
    parent_el = field_el.getparent()
    parent_raw = parent_el.attrib.get("name") if parent_el is not None else None
    canon_parent = normalize(parent_raw, standard, is_parent=True)

    # WSMP: force parent to "wsmp" so it matches the table
    if standard == Standard.IEEE16093 and canon and canon.startswith("wsmp."):
        canon_parent = "wsmp"

    cat = classify(canon, field_el, standard)
    return FieldRecord(
        standard=standard,
        raw_name=raw,
        canonical_name=canon,
        canonical_parent=canon_parent,
        size=_size(field_el),
        show=field_el.attrib.get("show"),
        showname=field_el.attrib.get("showname"),
        category=cat,
        element=field_el,
    )

def extract_message_id(proto):
    for f in proto.iter("field"):
        if f.attrib.get("name", "").endswith(".messageId"):
            m = re.search(r"\d+", f.attrib.get("show", ""))
            if m:
                return int(m.group())
    return None

def discover_packet(packet):
    result = {"wsmp": [], "16092": [], "j2735": None}
    for proto in packet.iter("proto"):
        pname = (proto.attrib.get("name") or "").lower()
        # WSMP layer (proto-based) 
        if pname == "wsmp":
            for field in proto.iter("field"):
                raw = field.attrib.get("name", "")
                low = raw.lower()
                # WSMP fields
                if low.startswith("wsmp.") or low.startswith("ieee1609dot3."):
                    result["wsmp"].append(make_record(field, Standard.IEEE16093))
                # 1609.2 fields are nested INSIDE wsmp
                elif "1609dot2" in low:
                    result["16092"].append(make_record(field, Standard.IEEE16092))

        #  J2735 layer (proto-based, messageId dispatch) 
        elif pname == "j2735":
            msg_id = extract_message_id(proto)
            label = J2735_MESSAGE_IDS.get(msg_id)
            records = [make_record(f, Standard.J2735)
                       for f in proto.iter("field")]
            result["j2735"] = (label, msg_id, records)
    return result


#result
@dataclass
class EvalResult:
    parent: str
    field: str
    verdict: Verdict = Verdict.PASS  
    length: Optional[int] = None
    value: Optional[object] = None
    tag_ok: bool = True
    length_ok: bool = True
    value_ok: bool = True
    unverified: bool = False
    notes: str = ""

# EVALUATION METHODS 
def eval_min_max(val, v1, v2):
    return v1 <= val <= v2

def eval_octet_count(fieldlen, target):
    return 0 < fieldlen <= target

def eval_bit_string(showname, target_bitlen):
    m = re.findall(r"bit length (\d+)", showname or "")
    if not m:
        return False, "Incorrect format for bit string."
    field_bitlen = int(m[0])
    # Account for pad bits (?)
    pad = re.findall(r"(\d+) LSB pad bits", showname or "")
    if pad:
        field_bitlen -= int(pad[0])
    return (field_bitlen <= target_bitlen), ""

def eval_boolean(val):
    return val in (0, 1)

def eval_hashalg(showname):
    m = re.findall(r"[Hh]ash(?:Algorithm|Id)?: (\w+)", showname or "")
    if not m:
        m = re.findall(r": (\w+)", showname or "")
    return bool(m) and m[0] in ("sha256", "sha384", "sm3")

def eval_ia5(fieldval, fieldlen, minlen, maxlen):
    if fieldlen < minlen or fieldlen > maxlen:
        return False
    try:
        (fieldval or "").encode("ascii")
    except UnicodeEncodeError:
        return False
    return True

def eval_utf8(fieldval, fieldlen, minlen, maxlen):
    if not (minlen == 0 and maxlen == 0):  # 0,0 = no length restriction
        if fieldlen < minlen or fieldlen > maxlen:
            return False
    try:
        (fieldval or "").encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True

def eval_signer(showname):
    m = re.findall(r"signer: (\w+)", showname or "")
    return bool(m) and m[0] in ("digest", "certificate")

def eval_seq_count(element, minitems, maxitems):
    ####Method 8: count child elements / read sequence_of_length
    for child in element.iter("field"):
        if child.attrib.get("name", "").endswith("sequence_of_length"):
            m = re.search(r"\d+", child.attrib.get("show", ""))
            if m:
                count = int(m.group())
                return minitems <= count <= maxitems
            
    # Fallback: count direct child <field> elements
    count = len(element.findall("field"))
    return minitems <= count <= maxitems

# RULE RESOLUTION
def resolve_rule_fast(lookup, parent, fieldname):
    rule = lookup.get((parent, fieldname))
    if rule is not None:
        return "MATCHED", rule
    return "UNMAPPED", None

# FIELD EVALUATION
def _parse_value(element):
    ###Extract an integer value from show (decimal) or value (hex)
    show = element.attrib.get("show")
    if show is not None:
        try:
            return int(show, 10)
        except (ValueError, TypeError):
            pass
    val = element.attrib.get("value")
    if val is not None:
        try:
            return int(val, 16)
        except (ValueError, TypeError):
            pass
    return None

def evaluate_field(record, rule, msg_type=None):
    #Evaluate one matched DATA field against its rule.
    #Returns an EvalResult.
    
    parent = record.canonical_parent
    fieldname = record.canonical_name
    method = int(rule["eval method"])
    tlen_ref = int(rule["length"])
    v1 = rule["val1"]
    v2 = rule["val2"]
    res = EvalResult(parent=parent, field=fieldname, length=record.size, value=None)
    
    # ASN.1 NULL fields - presence is sufficient
    if (parent, fieldname) in NULL_FIELDS:
        res.verdict = Verdict.PASS
        return res

    # Mark unverified fields
    if (parent, fieldname) in UNVERIFIED_FIELDS or msg_type in UNVERIFIED_MESSAGE_TYPES:
        res.unverified = True
    showname = record.showname or ""
    element = record.element
    
    # LENGTH check
    if method not in (4, 5, 6, 7, 8):
        flen = record.size if record.size is not None else -1

        if flen < 1 or flen > tlen_ref:
            res.length_ok = False
            res.notes += f"Incorrect length: {flen} (expected 1..{tlen_ref}). "

    # VALUE check by method
    try:
        if method == 0:  # min/max
            val = _parse_value(element)
            res.value = val
            if val is None:
                res.value_ok = False
                res.notes += "Unable to parse value. "
            else:
                res.value_ok = eval_min_max(val, v1, v2)
        elif method == 1:  # octet count
            flen = record.size or 0
            res.value = flen
            res.value_ok = eval_octet_count(flen, v1)
        elif method == 2:  # bit string
            ok, note = eval_bit_string(showname, v1)
            res.value_ok = ok
            if note:
                res.notes += note + " "
        elif method == 3:  # boolean
            val = _parse_value(element)
            res.value = val
            res.value_ok = (val is not None) and eval_boolean(val)
        elif method == 4:  # hashalg list
            res.value_ok = eval_hashalg(showname)
        elif method == 5:  # IA5 string
            strval = _extract_string(showname)
            res.value = strval
            res.value_ok = eval_ia5(strval, record.size or 0, v1, v2)
        elif method == 6:  # UTF8 string
            strval = _extract_string(showname)
            res.value = strval
            res.value_ok = eval_utf8(strval, record.size or 0, v1, v2)
        elif method == 7:  # signer
            res.value_ok = eval_signer(showname)
        elif method == 8:  # sequence-of item count
            res.value_ok = eval_seq_count(element, v1, v2)
        else:
            res.value_ok = False
            res.notes += f"Invalid evaluation method {method}. "
    except Exception as e:
        res.value_ok = False
        res.notes += f"Evaluation error: {e}. "


    # Final verdict !!
    if not res.value_ok:
        res.notes += "Value out of range/invalid. "
    if res.tag_ok and res.length_ok and res.value_ok:
        res.verdict = Verdict.PASS
    else:
        res.verdict = Verdict.FAIL
    return res

def _extract_string(showname):
    #Pull the string value from a showname
    m = re.findall(r": (.+)$", showname or "")
    return m[0] if m else ""


def summarize_records(records):
    #Count records by category
    counts = {}
    for r in records:
        counts[r.category] = counts.get(r.category, 0) + 1
    return counts


IEEE16092_TABLE = ieee16092_spdu_refdf
WSMP_TABLE = ieee16093_wsmp_refdf


class FailLog:
    #Deduplicated failure log (standard, message, parent, field)
    def __init__(self):
        self.rows = {}   # key -> dict

    def add(self, standard, message, result: "EvalResult"):
        key = (standard, message, result.parent, result.field)
        if key in self.rows:
            row = self.rows[key]
            row["occurrences"] += 1

            # merge any new note text
            if result.notes and result.notes.strip() not in row["notes"]:
                row["notes"] += " | " + result.notes.strip()

        else:
            self.rows[key] = {
                "standard": standard,
                "message": message,
                "parent": result.parent,
                "field": result.field,
                "sample_length": result.length,
                "sample_value": result.value,
                "occurrences": 1,
                "notes": result.notes.strip(),
                "unverified": result.unverified,
            }

    def is_empty(self):
        return len(self.rows) == 0

    def as_list(self):
        return list(self.rows.values())


class SkipLog:
    #Deduplicated log of skipped and unverified/unmapped fields (standard, category, parent, field).
    def __init__(self):
        self.rows = defaultdict(int)   
    def add(self, standard, category, parent, field):
        self.rows[(standard, category, parent, field)] += 1

    def as_list(self):
        return [
            {"standard": s, "category": c, "parent": p, "field": f, "occurrences": n}
            for (s, c, p, f), n in sorted(self.rows.items())
        ]


def evaluate_records(records, lookup, standard_label, message_label, faillog, skiplog, provisional=False):
    #Evaluate a list of FieldRecords against a reference lookup dict.
    #   Returns True if all evaluated fields passed (this layer conformant).
    
    layer_ok = True
    for r in records:
        # Non-DATA fields -> skip log
        if r.category != Category.DATA:
            skiplog.add(standard_label, r.category.value,
                        r.canonical_parent, r.canonical_name)
            continue

        status, rule = resolve_rule_fast(lookup, r.canonical_parent, r.canonical_name)

        if status == "MATCHED":
            result = evaluate_field(r, rule, msg_type=message_label)
            if provisional:
                result.unverified = True
            if result.verdict != Verdict.PASS:
                layer_ok = False
                faillog.add(standard_label, message_label, result)

        elif status == "UNMAPPED":
            skiplog.add(standard_label, "unmapped", r.canonical_parent, r.canonical_name)

        else:  # AMBIGUOUS?
            layer_ok = False
            amb = EvalResult(parent=r.canonical_parent,
                             field=r.canonical_name,
                             verdict=Verdict.AMBIGUOUS,
                             notes="Ambiguous: matched multiple table rules.")
            faillog.add(standard_label, message_label, amb)

    return layer_ok


# Pre-build fast lookup dicts once
def build_lookup(refdf):
    lookup = {}
    for _, row in refdf.iterrows():
        lookup[(row["parent"], row["field"])] = row.to_dict()
    return lookup

def build_mandatory_spec_cached(refdf):
    spec = {}
    for _, row in refdf.iterrows():
        if row["mandatory"] is True or str(row["mandatory"]).lower() == "true":
            spec.setdefault(row["parent"], []).append(row["field"])
    return spec

# Build all lookups ONCE
LOOKUPS = {
    "IEEE 1609.3::WSMP": build_lookup(WSMP_TABLE),
    "IEEE 1609.2::SPDU": build_lookup(IEEE16092_TABLE),
}
MANDATORY_SPECS = {
    "IEEE 1609.3::WSMP": build_mandatory_spec_cached(WSMP_TABLE),
    "IEEE 1609.2::SPDU": build_mandatory_spec_cached(IEEE16092_TABLE),
}
for lbl, df in J2735_TABLES.items():
    LOOKUPS[f"SAE J2735::{lbl}"] = build_lookup(df)
    MANDATORY_SPECS[f"SAE J2735::{lbl}"] = build_mandatory_spec_cached(df)

#####
def analyze_file(pdml_path, verbose=False):
    tree = etree.parse(pdml_path)
    faillog = FailLog()
    skiplog = SkipLog()
    file_ok = True
    packet_count = 0
    layer_seen = {"wsmp": False, "16092": False, "j2735": False}
    j2735_msgs_seen = set()
    rsa_seen = False

    for packet in tree.getroot():
        if packet.tag != "packet":
            continue
        packet_count += 1
        layers = discover_packet(packet)

        # --- WSMP (IEEE 1609.3) ---
        if layers["wsmp"]:
            layer_seen["wsmp"] = True
            ok = evaluate_records(layers["wsmp"],
                                  LOOKUPS["IEEE 1609.3::WSMP"],
                                  "IEEE 1609.3", "WSMP", faillog, skiplog)
            sok = check_structure(layers["wsmp"], WSMP_TABLE,
                                  "IEEE 1609.3", "WSMP", faillog, flat=True)
            file_ok = file_ok and ok and sok

        # --- IEEE 1609.2 ---
        if layers["16092"]:
            layer_seen["16092"] = True
            ok = evaluate_records(layers["16092"],
                                  LOOKUPS["IEEE 1609.2::SPDU"],
                                  "IEEE 1609.2", "SPDU", faillog, skiplog)
            sok = check_structure(layers["16092"], IEEE16092_TABLE,
                                  "IEEE 1609.2", "SPDU", faillog)
            file_ok = file_ok and ok and sok

        # --- SAE J2735 ---
        if layers["j2735"] is not None:
            layer_seen["j2735"] = True
            label, msg_id, records = layers["j2735"]
            if label is None:
                skiplog.add("SAE J2735", "unknown_message",
                            f"messageId={msg_id}", "")
                continue
            j2735_msgs_seen.add(label)

            lookup = LOOKUPS.get(f"SAE J2735::{label}")
            table = J2735_TABLES.get(label)
            if lookup is None or table is None:
                skiplog.add("SAE J2735", "no_table", label, "")
                continue

            provisional = (label == "RSA")
            if provisional:
                rsa_seen = True

            ok = evaluate_records(records, lookup, "SAE J2735", label,
                                  faillog, skiplog, provisional=provisional)
            sok = check_structure(records, table, "SAE J2735", label,
                                  faillog, provisional=provisional)
            file_ok = file_ok and ok and sok

    stats = {
        "packets": packet_count,
        "layers_seen": layer_seen,
        "j2735_msgs": sorted(j2735_msgs_seen),
        "rsa_seen": rsa_seen,
    }
    return file_ok, faillog, skiplog, stats


# create formatted, huaman readable report
def print_report(pdml_path, file_ok, faillog, skiplog, stats, verbose=False):
    print("\n" + "=" * 78)
    print(f"CONFORMANCE REPORT: {pdml_path}")
    print("=" * 78)
    print(f"  Packets analyzed : {stats['packets']}")
    seen = [k for k, v in stats["layers_seen"].items() if v]
    print(f"  Layers found     : {', '.join(seen) if seen else '(none)'}")
    print(f"  J2735 messages   : {', '.join(stats['j2735_msgs']) or '(none)'}")

    if stats["rsa_seen"]:
        print("\n  " + "!" * 60)
        print("  NOTE: RSA messages were evaluated. The RSA reference table is")
        print("  UNVALIDATED (no RSA traffic was available for validation).")
        print("  RSA results are PROVISIONAL.")
        print("  " + "!" * 60)

    #  Overall verdict
    print("\n" + "-" * 78)
    if file_ok:
        print("  FILE CONFORMANCE: PASS")
    else:
        print("  FILE CONFORMANCE: FAIL")
    print("-" * 78)

    # Unmapped / unvalidated notice (normal mode)
    skip_rows = skiplog.as_list()
    unmapped_rows = [r for r in skip_rows if r["category"] == "unmapped"]
    if unmapped_rows:
        unique_unmapped = len(unmapped_rows)
        total_occ = sum(r["occurrences"] for r in unmapped_rows)
        print(f"\n  NOTE: {unique_unmapped} unique DATA field(s) UNMAPPED ")
        print(f"        Run with --verbose to list them.")

    # fail log 
    if not faillog.is_empty():
        print(f"\n  FAILURES ({len(faillog.as_list())} unique):")
        print(f"  {'standard':<14}{'message':<8}{'parent':<40}"
              f"{'field':<28}{'occ':>6}  notes")
        for row in sorted(faillog.as_list(),
                          key=lambda x: (x["standard"], x["message"],
                                         x["parent"], x["field"])):
            prov = " [PROVISIONAL]" if row["unverified"] else ""
            print(f"  {row['standard']:<14}{row['message']:<8}"
                  f"{row['parent']:<40}{row['field']:<28}"
                  f"{row['occurrences']:>6}  {row['notes']}{prov}")

    # Skipped / unverified log (verbose only)
    if verbose:
        skip_rows = skiplog.as_list()
        if skip_rows:
            print(f"\n  SKIPPED FIELDS BY CATEGORY ({len(skip_rows)} unique) [--verbose]:")
            print(f"  (categories: container/bitstring/encoding/reserved = intentional; "
                    f"unmapped = coverage gap)")
            print(f"  {'standard':<14}{'category':<16}{'parent':<40}"
                  f"{'field':<28}{'occ':>6}")
            for row in skip_rows:
                print(f"  {row['standard']:<14}{row['category']:<16}"
                      f"{row['parent']:<40}{row['field']:<28}"
                      f"{row['occurrences']:>6}")

    print("\n" + "=" * 78)


def build_mandatory_spec(refdf):
    """
    From a reference table, build:
        { parent_name: [ordered list of mandatory field names] }
    The order follows the table's row order ( ASN.1 order)
    """
    spec = {}
    for _, row in refdf.iterrows():
        if row["mandatory"] is True or str(row["mandatory"]).lower() == "true":
            spec.setdefault(row["parent"], []).append(row["field"])
    return spec


def check_structure(records, refdf, standard_label, message_label, faillog, provisional=False, flat=False):
    """
    flat=True: treat ALL DATA fields in this layer as ONE logical instance
               Presence is checked; sequence is skipped

    flat=False: group fields by their actual parent element instance and check
                presence + sequence per instance (for nested protocols).
    """
    mandatory_spec = build_mandatory_spec(refdf)
    if not mandatory_spec:
        return True

    structure_ok = True

    # FLAT PROTOCOLS (WSMP)
    if flat:
        seen_fields = [r.canonical_name for r in records
                       if r.category == Category.DATA]
        seen_set = set(seen_fields)
        for ptype, expected in mandatory_spec.items():
            for mand_field in expected:
                if mand_field not in seen_set:
                    structure_ok = False
                    faillog.add(standard_label, message_label, EvalResult(
                        parent=ptype, field=mand_field, verdict=Verdict.FAIL,
                        value="MISSING", notes="Mandatory field missing.",
                        unverified=provisional))
            # Sequence intentionally NOT checked for flat protocols
        return structure_ok

    #  NESTED PROTOCOLS (J2735, 1609.2)
    instances = {}
    # Build instances from observed DATA fields
    for r in records:
        if r.category != Category.DATA:
            continue
        parent_el = r.element.getparent()
        if parent_el is None:
            continue
        pid = id(parent_el)
        inst = instances.setdefault(pid, {"ptype": r.canonical_parent,
                                          "fields": [], "element": parent_el})
        inst["fields"].append(r.canonical_name)

    # detect mandatory-parent ELEMENTS that exist in the tree but may have lost their mandatory DATA child
    known_ids = set(instances.keys())
    std = records[0].standard if records else None
    for r in records:
        anc = r.element.getparent()
        while anc is not None:
            aname = normalize(anc.attrib.get("name"), std, is_parent=True)
            if aname in mandatory_spec and id(anc) not in known_ids:
                instances[id(anc)] = {"ptype": aname, "fields": [],
                                      "element": anc}
                known_ids.add(id(anc))
            anc = anc.getparent()

    # Validate each instance (presence + sequence).
    for pid, inst in instances.items():
        ptype = inst["ptype"]
        expected = mandatory_spec.get(ptype)
        if not expected:
            continue

        seen_fields = inst["fields"]
        seen_set = set(seen_fields)

        # presence
        for mand_field in expected:
            if mand_field not in seen_set:
                structure_ok = False
                faillog.add(standard_label, message_label, EvalResult(
                    parent=ptype, field=mand_field, verdict=Verdict.FAIL,
                    value="MISSING", notes="Mandatory field missing.",
                    unverified=provisional))

        # sequence
        expected_order = [f for f in expected if f in seen_set]
        first_seen = []
        for f in seen_fields:
            if f in expected and f not in first_seen:
                first_seen.append(f)
        if first_seen != expected_order:
            structure_ok = False
            faillog.add(standard_label, message_label, EvalResult(
                parent=ptype, field="(sequence)", verdict=Verdict.FAIL,
                notes=(f"Mandatory field order mismatch. "
                       f"Expected {expected_order}, saw {first_seen}."),
                unverified=provisional))

    return structure_ok

# MAIN =====================================================================
def main():
    ap = argparse.ArgumentParser(
        description="V2X Conformance Analyzer (J2735 / IEEE 1609.2 / 1609.3)."
    )
    ap.add_argument("pdml", help="PDML file to analyze")
    ap.add_argument("--verbose", action="store_true",
                    help="Also show skipped/unmapped/unverified fields")
    
    start_time = time.time()

    args = ap.parse_args()

    file_ok, faillog, skiplog, stats = analyze_file(args.pdml, verbose=args.verbose)
    print_report(args.pdml, file_ok, faillog, skiplog, stats, verbose=args.verbose)
    
    end_time = time.time()
    print("\n*** Execution time:", (end_time - start_time)/60 , "minutes ***")


if __name__ == "__main__":
    main()

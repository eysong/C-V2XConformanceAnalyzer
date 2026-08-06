# C-V2X Message Conformance Analyzer
This repository contains a Python-based tool for evaluating the standards conformance of C-V2X messages. Given a PDML packet capture, it validates decoded fields across SAE J2735, IEEE 1609.2 and 1609.3 standards. The repository contains the knowledge tables derived from each of the three standards(ASN.1), which the analyzer uses to validate each matched field. The tool reports conformance issues including out-of-range values, incorrect field lengths, missing mandatory fields, and sequence violations, producing an overall pass/fail verdict with a detailed report.

## Supported Standards
* SAE J2735
    * Basic Safety Message (BSM)
    * Map Data (MAP)
    * Signal Phase and Timing (SPaT)
    * Roadside Alert (RSA) [PROVISIONAL - RSA fields have not been validated] 
    * Traveler Information Message (TIM)

* IEEE 1609.2
    * IEEE 1609.2 Signed Data

* IEEE 1609.3
    * WSMP

_The validator is designed to be extensible: additional SAE J2735 message types can be supported by adding new protocol reference tables and corresponding validation rules._

### Features
* Tag validation
* Field length validation
* Field value validation (9 evaluation methods)
* Mandatory field presence and sequence validation
* Optional field handling
* Vendor-independent field normalization
* Container/structural scope handling
* Detailed conformance reporting
* Field, message, packet, and file level compliance summaries

## Usage
The analyzer accepts a single PDML file. This tool can be run either from the command line or through a graphical interface.

### Requirements
* Python 3.14
* git
* Python packages: lxml, pandas, Pillow (installed via requirements.txt)
* Tkinter (for the GUI) — included with standard Python on Windows/macOS

1. Install git and Python 3
* Windows: Download git from git-scm.com and Python from python.org . During Python installation, check **"Add python.exe to PATH."** Then open Git Bash.
* Debian/Ubuntu Linux: ```sudo apt install git python3 python3-pip python3-tk```
* macOS: Install git and Python via python.org or Homebrew (```brew install git python```).


2. Clone this repository.
    ```shell
    git clone https://github.com/eysong/C-V2XConformanceAnalyzer.git
    cd C-V2XConformanceAnalyzer 
    ```
    
3. Install the required Python packages.
    ```shell
    pip install -r requirements.txt
    ```
    _Note: The GUI uses Tkinter, included with standard Python on Windows and macOS. On some Linux systems, install it separately with_ ```sudo apt install python3-tk```.

   
### Running the Analyzer
**Command Line**

Run the analyzer on a PDML file:
```shell
python src/cv2x_conform_analyzer.py <pdml_file> [optional flags]
```
| Argument     | Description                          |
|:---------:|:----------------------------|
| `<pdml_file>`    | (required) path to PDML file to analyze  | 
| `--finalverdict-only`  | Output only the summary verdict and failure log. Useful for quick pass/fail check.  |
| `--show-skipped`  | Include a table of all skipped and unmapped fields in the summary |
| `--outdir <DIR>`  |Specify directory to write the output report to. Defaults to current directory.|

Example:
```shell
python src/cv2x_conform_analyzer.py captures/commsigniaOBU4.pdml --show-skipped --outdir results/
```

By default, the program writes a report file `<filename>_report.txt` containing full TLV/compliance detail for each packet, rolled up to per-message/per-packet verdicts. The summary verdict and failure log is written to the end of this file. A summary is printed to the console.

**Graphical Interface**

Run the GUI with: 
```shell
python src/conform_analyzer_GUI.py
```
The interface provides:
* A file selector to designate what PDML is being analyzed
* Checkboxes equivalent to command-line options- final verdict only and/or show skipped fields
* Download button to save the complete report as a .txt file and select output directory
* Live packet-count progress during analysis and real-time detail showing per-field results
* A summary report box showing the overall verdict and fail log if applicable

**Output**
The analyzer produces:
* Console: a summary verdict (PASS/FAIL), layers and message types found, and a failure log if any conformance issues were detected.
* Report file (```<filename>_report.txt```): per-packet field detail (tag/length/value/compliance), message and packet verdicts, and the final summary.


## Validation Process
For every field in each supported protocol, the tool performs the following:
1. Field identification
    * normalizes the field and its parent name and matches them against the applicable reference table
    * fields with no matching rule are logged as unmapped
    * structural containers, encoding artifacts, and reserved fields are skipped

2. Length validation
    * verifies the field's encoded byte length against the standard
       * (skipped for string, hash, signer, and sequence-count checks, which validate content or item count rather than a fixed size)
  
3. Value validation
   * numeric ranges (min/max)
   * octet counts
   * bit strings
   * booleans
   * IA5 strings
   * UTF-8 strings
   * hash algorithms
   * signer types
   * sequence-of item counts

4. Structural validation
    * confirms that all mandatory fields are present within each message instance
    * confirms that for nested protocols, mandatory fields appear in the standard-defined order

5. Reporting
    * records each failure with its evaluation method and a sample value
    * collapses repeated failures with an occurrence count
    * rolls results up into field, message, packet, and overall file conformance verdicts
    * displays and writes full report to a human-readable file
  
## Reference Tables
Each supported message type has a reference table defining
* field name
* parent field
* maximum encoded length
* evaluation method
* reference values
* mandatory status

These tables are derived from the SAE J2735 and IEEE 1609.2/1609.3 standards. Each supported protocol holds its own reference table stored in an individual python module imported by the main analyzer (see src/).

## Vendor Compatibility
The tool has been validated with data from:
* Commsignia
* Denso
* ITTelComm
* Kapsch
* MioVision
* QualComm
with Cohda data being intentionally excluded.

### Vendor Differences
Supporting multiple vendors required handling differences in how their Wireshark PDML dissections represent the same fields. 

The normalization process handles:
* alternate protocol prefixes
* generated ASN.1 suffixes
* optional field representations
* numbered structure variants
* field aliases

These normalizations let captures from various vendor implementations to match the same set of reference tables.

## Limitations
Current limitations
* Requires Wireshark PDML input
* Reference tables must be updated for future standard revisions
* RSA is unvalidated
* WAVE IE contents are not individually validated - checked structurally only

## References
* [C-V2X Interoperability Analyzer](https://github.com/usnistgov/C-V2XInteroperabilityAnalyzer)
* SAE J2735 V2X Communications Message Set Dictionary - ASN.1
* [IEEE 1609.2 ASN.1](https://github.com/eabalea/1609dot2-asn)
* 2026 OmniAir MD Plugfest Datasets
* [C-V2X Message Exchange Process Assessment Tool](https://github.com/eysong/C-V2XMsgExchangeAssessingTool) (GUI)

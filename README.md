# C-V2X PDML Conformance Analyzer
This repository is a software tool to analyze the conformance of C-V2X messages based on testing packet datasets and SAE J2735, IEEE 1609.2 and 1609.3 standards. It compares decoded packet fields against reference tables derived from the standards and reports interoperability issues including invalid values, incorrect field lengths, missing or repeated fields, and sequence violations.

## Supported Standards
* SAE J2735
    * Basic Safety Message (BSM)
    * MAP
    * SPaT
    * Roadside Alert (RSA)
    * Traveler Information Message (TIM)

* IEEE 1609.2
    * Signed Data

* IEEE 1609.3
    * WSMP

_The validator is designed to be extensible. Additional SAE J2735 message types can be supported by adding new protocol reference tables and corresponding validation rules._

### Features
* Tag validation
* Field length validation
* Value validation
* Mandatory field sequence validation
* Optional field handling
* Vendor-independent field normalization
* Detailed interoperability failure reporting
* Packet, protocol, and file level compliance summaries

## Usage
1. Install git and Python 3.14. The installation procedure varies depending on your operating system.

* On Debian and Ubuntu Linux, run `sudo apt install git python3-pip` in a terminal.
    * On Windows, first download and install git from [here](https://git-scm.com/downloads/win), then download
      and install Python 3.14 from [here](https://www.python.org/downloads/). Make sure to select "Add python.exe
      to PATH" in the Python installer. Open a Git Bash terminal and navigate to the relevant directory.

2. Install [PDM](https://pdm-project.org/). For example, using plain pip:

    ```shell
    pip install -U --user pdm
    ```

    Refer to the [PDM documentation](https://pdm-project.org/en/latest/#installation) for more installation options.

3. Clone this repository.

    ```shell
    git clone [https://github.com/usnistgov/C-V2XInteroperabilityAnalyzer.git](https://github.com/eysong/C-V2XConformanceAnalyzer)
    cd C-V2XConformanceAnalyzer
    ```

4. Install all required Python packages.

    ```shell
    pip install -r requirements.txt
    ```

5. Run the analyzer with the target PDML file name as argument.

    ```shell
    python src/cv2x-interop-analyzer_new.py example.pdml
    ```

    By default the output is printed to stdout, but can be redirected or piped to a text file using the shell.

    ```shell
    python src/cv2x-interop-analyzer_new.py example.pdml > output.txt
    python src/cv2x-interop-analyzer_new.py example.pdml | tee output.txt
    ```

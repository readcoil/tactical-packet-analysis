# tactical-packet-analysis
This repository contains a proof of concept tool to automate pcap analysis using Spotify's luigi framework (https://github.com/spotify/luigi).

The tool consists of various tasks that are used to progressively segment and process traffic to retain source data and enable additional manual analysis. 
The luigi framework enables the implementation of modular, stackable tasks that can be extended to further analysis as required.

A flask dashboard is also included as a helper to automate basic processing and visualization of results.

Visualization is achieved using the data exploration libraries pandas and dtale (https://github.com/man-group/dtale).

#### Implementation Notes:
This is a proof of concept tool and is not intended for production use. It was originally developed to illustrate the concepts presented in the talk "Tactical Packet Analysis" at the 2024 SANS Europe ICS Summit. It may or may not be maintained, however pull requests for initial issues are very welcomed.

The modules deliberately leverage os-level commands to run tshark and other tools to demonstrate the ease of integration with existing tools. 
In addition, a custom strings tool (https://github.com/readcoil/strictstrings) is included to extract strings from protocol-segmented pcap files.

## Installation
1. Clone the repository
2. Install the required packages using the requirements.txt file
```
pip install -r requirements.txt
```
3. Install host-based requirements
* https://github.com/ntop/nDPI
* https://github.com/topics/tshark

Tshark:
```bash
sudo apt-get update
sudo apt-get install tshark
```

NDPI (Ubuntu 22.04) (Note; POC requires version 4.4.0):
https://github.com/ntop/nDPI/tree/4.4-stable

If you're on Mac, you can install with:
```
brew install ndpi
```

4. Install strictstrings from https://github.com/readcoil/strictstrings (or modify the ExtractStrings task to use the native strings tool)
4. Ensure all host tools are installed and executable from the command line
```
tshark --version
ndpireader --version
capinfos --version
strictstrings --version
tcpdump --version
```
5. Run the dashboard
```
python -m tpahelper
```


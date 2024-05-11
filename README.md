# tactical-packet-analysis
This repository contains a proof of concept tool to automate pcap analysis using Spotify's luigi framework (https://github.com/spotify/luigi).

The tool consists of various tasks that can be used to automate the analysis of pcap files. 
The luigi framework enables the implementation of modular, stackable tasks that can be easily extended to include additional analysis.

A dashboard is also included as a helper to automate the process of running the tasks and visualizing the results.

Visualization is achieved using the data exploration libraries pandas and dtale (https://github.com/man-group/dtale).

The modules deliberately leverage os-level commands to run tshark and other tools to demonstrate the ease of integration with existing tools. 
In addition, a custom strings tool is included to extract strings from protocol-segmented pcap files. 


## Installation
1. Clone the repository
2. Install the required packages using the requirements.txt file
```
pip install -r requirements.txt
```
3. Install host-based requirements
```
sudo apt-get install tshark ndpireader
```
4. Run the dashboard
```
python -m tpahelper
```


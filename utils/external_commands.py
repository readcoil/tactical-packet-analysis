# Description: This file contains the tshark fields present in the pcap file.
# The fields are extracted by dumping a json representation of the pcap, then
# using command line tools to process the output.
# The fields are then used for later analysis.

# Positional arguments:
# 1. pcap file
# 2. output file
# extract_protocol_fields = (
#     """tshark -r "{}" -T json | jq 'map(.. | keys? | """
#     """select(. != null)) | add | unique' | grep -v ':' | """
#     """awk -F'"' '{{print $2}}' | sort | egrep '^[a-zA-Z0-9_.]+$' """
#     """> "{}" """
# )

extract_protocol_fields = (
    """tshark -r \"{}\" -T json | jq -r '[.. | objects | keys[]] | unique[]' | grep '^[a-zA-Z0-9_.]+$' > \"{}\" """
)

# Description: Extracts the unique strings from the pcap file.
# Leverages "strictstrings" tool to filter language-like strings,
# then post processes based on similarity to remove similar duplicates,
# like timestamps etc.

# Positional arguments:
# 1. pcap file
# 2. output file
extract_unique_strings = """strictstrings {} -q > {}"""

# Description: Extracts the statistics from the pcap using tshark
# Positional arguments:
# 1. pcap file
# 2. output file
execute_pcap_stats = """tshark -r {} -q -z io,phs > {}"""

# Description: Extracts the statistics from the pcap using capinfos
# Positional arguments:
# 1. pcap file
# 2. output file
execute_capinfos = "capinfos -TmQ {} > {}"

# Description: Dumps a specific flow to an output pcap file.
# Positional arguments:
# 1. pcap file
# 2. output pcap file
# 3. src ip
# 4. dst ip
# 5. src port
# 6. dst port
tcpdump_flow = (
    """tcpdump -r "{}" -nn -v -w "{}" """
    """host {} and host {} and """
    """port {} and port {}"""
)

# Description: Dumps a specific protocol to an output pcap file.
# Note: additional filters expected to be prepended to the command.
# for demo purposes, the ndpi_protocol_map file in utils is used
# to get the additional filters.
# Positional arguments:
# 1. pcap file
# 2. output pcap file
tcpdump_protocol = (
    """tcpdump -r {} -nn -v -w {} {} """
)

# Description: Dumps a specific protocol to an output pcap file.
# Note: additional filters expected to be prepended to the command.
# for demo purposes, the ndpi_protocol_map file in utils is used
# to get the additional filters.
# Positional arguments:
# 1. pcap file
# 2. protocol filter
# 3. output pcap file
tshark_protocol = (
    """tshark -r {} -w {} -Y {} """
)

# Description: Extracts the ndpiReader data from a pcap file,
# and stores the stdout stats in a separate file.
# Positional arguments:
# 1. pcap file
# 2. stats file
# 3. summary file
ndpi_extract = "ndpiReader -i {} -K json -k {} > {}"


# Description: Queries specific indicator values using the AlienVault OTX API.
# Positional arguments:
# 1. indicator value
# 2. output file
otx_ipv4 = "https://otx.alienvault.com/api/v1/indicators/IPv4/{}/general"
otx_ipv6 = "https://otx.alienvault.com/api/v1/indicators/IPv6/{}/general"
otx_domain = "https://otx.alienvault.com/api/v1/indicators/domain/{}/general"
otx_url = "https://otx.alienvault.com/api/v1/indicators/url/{}/general"
otx_hostname = "https://otx.alienvault.com/api/v1/indicators/hostname/{}/general"

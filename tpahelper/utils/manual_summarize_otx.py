# script to summarize the OTX data output if the pipeline is stopped.
# pcaps with a high number of public ips will have troubles completing the task.
# to be fixed.

import glob
import json
import os
import pandas as pd
from pandas import json_normalize

from tpahelper.utils.html_templates import datatable_template


pcap_name = 'eth_miner'
base_dir = os.path.abspath(os.path.dirname(__file__))
indicator_path = os.path.join(base_dir, f'../processed/{pcap_name}/indicators/')
raw_indicator_path = os.path.join(indicator_path, 'raw')
otx_files = glob.glob(f'{raw_indicator_path}/*.json')

out_parquet = os.path.join(indicator_path, "ip_reputation.parquet")
out_html = os.path.join(indicator_path, "ip_reputation.html")

main_df_list = []
pulses_df_list = []

if not otx_files:
    raise FileNotFoundError(f"No OTX files found in {raw_indicator_path}")

for file in otx_files:
    with open(file, 'r') as infile:
        data = json.load(infile)

        # Normalize main data, excluding the deeply nested 'pulses' first
        this_df = json_normalize(data)
        if 'pulse_info.pulses' in this_df.columns:
            this_df.drop(columns=['pulse_info.pulses'], inplace=True)

        # Store each main DataFrame to list
        main_df_list.append(this_df)

        # Check if 'pulse_info.pulses' is present and process if available
        if 'pulse_info.pulses' in data:
            # Normalize pulses data
            pulses = json_normalize(data, record_path=['pulse_info', 'pulses'])
            # Add an identifier if necessary (e.g., from the main data)
            if 'indicator' in this_df.columns:
                pulses['indicator'] = data['indicator']
            pulses_df_list.append(pulses)

# Concatenate all main dataframes into a single DataFrame
main_df = pd.concat(main_df_list, ignore_index=True, sort=False)

# Concatenate all pulses dataframes into a single DataFrame
if pulses_df_list:
    pulses_df = pd.concat(pulses_df_list, ignore_index=True, sort=False)

    # Join pulses to the main DataFrame based on an identifier or directly if the order is preserved
    # Here we assume 'indicator' to be the linking column; adjust as necessary
    df = pd.merge(main_df, pulses_df, on='indicator', how='left', suffixes=('', '_pulse'))
else:
    df = main_df  # No pulses data to merge

# Write the DataFrame to parquet file
df.to_parquet(out_parquet)
html_table = df.to_html(classes='display', index=False, table_id='dataTable')

page = datatable_template.format(html_table)
with open(out_html, 'w') as out_file:
    out_file.write(page)
import pandas as pd
import dpath
import json
import os
import subprocess
from termcolor import colored
from tabulate import tabulate
from loguru import logger
import ijson
import numpy as np
import plotly.express as px

from statsmodels.tsa.stattools import acf
from statsmodels.graphics.tsaplots import plot_acf
import matplotlib.pyplot as plt
from scipy.signal import find_peaks

def read_json_lines_generator(json_file):
    """Generator to read a file with each line as a separate JSON object."""
    with open(json_file, 'r') as file:
        for line in file:
            yield json.loads(line)


def read_json_doc_generator(file_path):
    """Generator to read a JSON file with each object as a separate JSON document."""
    with open(file_path, 'rb') as file:
        objects = ijson.items(file, 'item')
        for obj in objects:
            yield obj


class DNP3Processor:
    name = 'DNP3'

    def __init__(self, infile, outpath):
        self.infile = infile
        self.outpath = outpath
        self.output_json = os.path.join(self.outpath, "target_dnp3.json")
        self.output_parquet = os.path.join(self.outpath, "dnp3_values.parquet")
        self.output_html = os.path.join(self.outpath, "dnp3_point_value_charts.html")
        self.dnp3_types = ['int', 'double', 'float']
        self.dnp3_point_types = ['dnp3.al.ana.', 'dnp3.al.anaout.']
        self.target_points = [p + t for p in self.dnp3_point_types for t in self.dnp3_types]
        self.target_string = ' '.join(f"-j {point}" for point in self.target_points)

    def run(self) -> list:
        print(colored(f"\nConverting target DNP3 fields to json", 'green'))
        self.dnp3_to_json()

        print(colored(f"\nExtracting point values", 'green'))
        all_point_values = []
        for line in read_json_doc_generator(self.output_json):
            for target_point in self.target_points:
                point_values = self.extract_point_values(line, target_point,
                                                          custom_timestamp="dnp3.al.timestamp")

                if point_values:
                    all_point_values += point_values

        df = pd.DataFrame(all_point_values)

        ### Convert the dataframe to a timeseries ###
        # Convert 'dnp3.al.timestamp' to datetime
        df['frame.time'] = pd.to_datetime(df['frame.time'])

        # Ensure 'value' column is numeric.
        df['value'] = pd.to_numeric(df['value'], errors='coerce')

        # Set the index to 'dnp3.al.timestamp' and keep only the necessary columns
        df = df[['frame.time', 'al.index', 'value']].set_index('frame.time')

        # Group by 'al.index', resample, and calculate mean only for 'value'
        df_resampled = df.groupby('al.index').resample('1s').agg({'value': 'mean'}).dropna(
            subset=['value']).reset_index()

        # Pivot the DataFrame to get 'al.index' as columns
        df_pivot = df_resampled.pivot(index='frame.time', columns='al.index', values='value').fillna(0)

        # Reset index to make 'dnp3.al.timestamp' a column again for plotting
        df_pivot.reset_index(inplace=True)


        print(colored("\nDataframe head:", 'blue'))
        print(colored(tabulate(df_pivot.head(), headers='keys', tablefmt='psql'), 'green'))

        # # Write df to parquet
        df_pivot.to_parquet(self.output_parquet, index=False)

        self.visualize_point_values()

        return [self.output_json, self.output_parquet, self.output_html]

    def dnp3_to_json(self):
        command = (
            f"tshark -r {self.infile} -T json -O json -J frame "
            f"-j frame.time -j frame.time_utc -J ip -j ip.src -j ip.dst -J dnp3 "
            f"{self.target_string} > {self.output_json}"
        )

        print(colored("\nExecuting command:", "yellow"))
        print(colored(f"{command}\n", "blue"))

        # blocking call for testing / execution profiling purposes
        result = subprocess.run(command,
                                capture_output=True,
                                text=True,
                                shell=True)

        if result.stdout:
            print(f"\t{result.stdout}")
        elif result.stderr:
            print(f"\tError: {result.stderr}")
        else:
            print("\tNo output")

    @logger.catch
    def extract_point_values(self, packet: dict, target_field: str, _filter: str = None,
                              custom_timestamp: str = None) -> list:
        all_values = []
        filter_search = None
        if _filter:
            filter_search = dpath.search(packet, f'**/{_filter}', yielded=True)

        target_field_search = list(dpath.search(packet, f'**/{target_field}', yielded=True))

        if (filter_search or not _filter) and target_field_search:
            time_search = list(dpath.search(packet, '**/frame.time', yielded=True))
            utc_time_search = list(dpath.search(packet, '**/frame.time_utc', yielded=True))

            custom_timestamps = []
            if custom_timestamp:
                custom_timestamp_search = dpath.search(packet, f'**/{custom_timestamp}', yielded=True)
                custom_timestamps = [ts for p, ts in custom_timestamp_search]

            point_number_search = dpath.search(packet, f'**/dnp3.al.index', yielded=True)
            point_numbers = [v for p, v in point_number_search]

            point_value_search = dpath.search(packet, f'**/{target_field}', yielded=True)
            point_values = [v for p, v in point_value_search]

            if len(custom_timestamps) == len(point_numbers) == len(point_values):
                for ts, pn, pv in zip(custom_timestamps, point_numbers, point_values):
                    all_values.append({
                        'type': target_field,
                        'frame.time': time_search[0][1] if time_search else None,
                        'frame.time_utc': utc_time_search[0][1] if utc_time_search else None,
                        'dnp3.al.timestamp': ts,
                        'al.index': pn,
                        'value': pv
                    })

            else:
                for pn, pv in zip(point_numbers, point_values):
                    all_values.append({
                        'type': target_field,
                        'frame.time': time_search[0][1] if time_search else None,
                        'frame.time_utc': utc_time_search[0][1] if utc_time_search else None,
                        'dnp3.al.timestamp': None,
                        'al.index': pn,
                        'value': pv
                    })

        return all_values

    def visualize_point_values(self):
        print(colored("\nCreating DNP3 charts", 'green'))

        # read parquet file to dataframe
        df = pd.read_parquet(self.output_parquet)
        if df.empty:
            print(colored("Dataframe is empty", 'red'))
            with open(self.output_html, 'w') as f:
                f.write("<h1>No DNP3 point values.</h1>")
            return

        # Plot using Plotly
        fig = px.line(df, x='frame.time', y=df.columns[1:],
                      title='Averaged Values per AL Index Every Second',
                      labels={'value': 'Averaged Value', 'frame.time': 'Timestamp', 'variable': 'AL Index'})

        # Update legend to show 'AL Index'
        fig.update_layout(legend_title_text='AL Index')

        # Save the plot to an HTML file
        fig.write_html(self.output_html)

    def fft_period_estimate(df: pd.DataFrame, column: str):
        # Ensure column exists
        if column not in df.columns:
            raise ValueError(f"Column {column} not found in DataFrame")

        # Resample and forward fill
        records = df[column].resample('1s').mean().ffill()

        # Calculate the Fourier transform
        yf = np.fft.fft(records)
        n = len(records)
        T = 1.0  # spacing between points if fs = 1 Hz
        xf = np.fft.fftfreq(n, T)[:n // 2]  # Get only the positive frequencies

        # Drop the DC component and find the index of the peak in the FFT magnitude
        idx = np.argmax(np.abs(yf[1:n // 2])) + 1  # +1 to correct the index for the DC component
        peak_freq = xf[idx]
        period = 1 / peak_freq if peak_freq != 0 else np.inf  # Handle division by zero

        print(f"The period of the time series is {period} seconds")

        # Plot the periodogram
        plt.figure(figsize=(10, 5))
        plt.plot(xf, 2.0 / n * np.abs(yf[0:n // 2]))  # Plotting only the positive frequencies
        plt.xlabel('Frequency (Hz)')
        plt.ylabel('Magnitude')
        plt.title('FFT Magnitude Spectrum')
        plt.grid(True)
        plt.show()

        return period

    def plot_pandas_autocorrelation(df: pd.DataFrame, column: str, lags: int = None):
        if not lags:
            lags = get_recommended_lags(df)
            print(f"Recommended Lags: {lags}")

        df = df.resample('1s').mean().ffill()
        fig, ax = plt.subplots(figsize=(20, 10))

        pd.plotting.autocorrelation_plot(df[column], ax=ax)

        plt.show()

def autocorrelation_peaks(df: pd.DataFrame, column: str, lags: int = None):
    if column not in df.columns:
        raise ValueError(f"Column {column} not found in DataFrame")

    if not lags:
        lags = get_recommended_lags(df)
        print(f"Recommended Lags: {lags}")

    # Resampling and forward filling the DataFrame
    df = df.resample('1s').mean().ffill()

    # Calculate autocorrelation manually using a list comprehension
    autocorr = [df[column].autocorr(lag=i) for i in range(lags)]

    # Finding peaks in the autocorrelation to suggest periodicity
    peaks, _ = find_peaks(autocorr, height=0)  # Adjust parameters as needed for better peak detection

    if peaks.size > 0:
        print("Potential periods at lags:", peaks)

    return peaks  # Returning the lags where peaks were found


def get_recommended_lags(df):
    data_frequency = df.index.freqstr

    # Suggest a number of lags based on frequency
    if data_frequency:
        if 'D' in data_frequency:  # daily data
            recommended_lags = min(df.shape[0] // 10, 30)  # no more than 30 days
        elif 'H' in data_frequency:  # hourly data
            recommended_lags = min(df.shape[0] // 10, 24)  # no more than 24 hours
        elif 'T' in data_frequency:  # minute data
            recommended_lags = min(df.shape[0] // 10, 60)  # no more than 60 minutes
        else:
            recommended_lags = df.shape[0] // 10
    else:
        # Generic fallback if frequency is undefined
        recommended_lags = df.shape[0] // 10

    return recommended_lags


def plot_acf_df(df: pd.DataFrame, column: str, lags: int = None):
    df_resampled = df.resample('1s').mean()
    if not lags:
        lags = get_recommended_lags(df)
        print(f"Recommended Lags: {lags}")

    if column not in df.columns:
        raise ValueError(f"Column {column} not found in DataFrame")

    if not lags == 0:
        plot_acf(df[column], lags=lags, alpha=0.05)
    else:
        plot_acf(df[column], lags=df.shape[0] // 2, alpha=0.05)

    plt.title(f"Autocorrelation of column: {column}")
    plt.xlabel("Lags")
    plt.ylabel("Autocorrelation")
    plt.grid()
    plt.gcf().set_size_inches(20, 10)
    plt.show()


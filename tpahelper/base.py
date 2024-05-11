import ipaddress
import luigi
import os
import pandas as pd
import subprocess
from tpahelper.config import config


def get_output_path(self):
    return os.path.join(self.output_dir, self.pcap_name.replace('.pcap', ''))


class BaseTask(luigi.Task):
    pcap_file = luigi.Parameter()
    output_dir = luigi.Parameter(default=config.OUTPUT_DIR)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Ensure all parameters are initialized before setting this.
        self.pcap_name = str(self.pcap_file).split('/')[-1]

    def output_path(self):
        return os.path.join(self.output_dir, self.pcap_name.replace('.pcap', ''))

    def task_output_path(self, task_path:str):
        return os.path.join(self.output_path(), task_path)

    def param_dict(self):
        return {'pcap_file': self.pcap_file, 'output_dir': self.output_dir}
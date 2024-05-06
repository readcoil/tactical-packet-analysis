import os
import csv
import json
import pandas as pd
import ipaddress
import subprocess
import time
from tabulate import tabulate
from loguru import logger
import luigi
from multiprocessing import Process
from dtale.app import build_app
from dtale.global_state import cleanup
from dtale.views import startup
from flask import (
    Flask,
    request,
    render_template,
    render_template_string,
    redirect,
    url_for,
    flash,
    jsonify,
    send_file,
    send_from_directory,
    make_response,
)

from markupsafe import escape
from werkzeug.utils import secure_filename
from ydata_profiling import ProfileReport

from tpahelper.config import config
from tpahelper.analyze_pcap import AllTasks

# app = Flask(__name__)
# app.secret_key = "shouldntreallymatterwhatthisis_demoapponly"

# Ensure the upload folder exists
os.makedirs(config.UPLOAD_FOLDER, exist_ok=True)


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in config.ALLOWED_EXTENSIONS

def run_luigi_task_in_subprocess(filename):
    print(f"Running luigi task for {filename}")
    pcap_path = os.path.join(config.UPLOAD_FOLDER, filename)

    # Run luigi process_pcap module / AllTasks
    luigi.configuration.get_config().set('core', 'no_lock', 'True')
    task = AllTasks(pcap_file=pcap_path)
    luigi.build([task], workers=config.WORKERS)

def check_task_status(filename):
    # Checks for the presence of the following files:
    # queue.txt, done.txt, and failed.txt in the output directory
    pcap_path = os.path.join(config.UPLOAD_FOLDER, filename)
    output_path = os.path.join(config.OUTPUT_DIR, filename.replace('.pcap', ''))
    queue_file = os.path.join(output_path, 'task_created.txt')
    done_file = os.path.join(output_path, 'all_tasks_complete.txt')
    failed_file = os.path.join(output_path, 'did_not_complete.txt')

    if os.path.exists(done_file):
        return "done"
    elif os.path.exists(failed_file):
        return "failed"
    elif os.path.exists(queue_file) and not os.path.exists(done_file) and not os.path.exists(failed_file):
        return "running"
    else:
        return "new"

def get_output_files(filename):
    output_path = os.path.join(config.OUTPUT_DIR, filename.replace('.pcap', ''))
    flows = os.path.join(output_path, 'ndpi_flows.parquet')
    ndpi_summary = os.path.join(output_path, 'ndpi_summary.txt')
    ip_rep = os.path.join(output_path, 'indicators/ip_reputation.parquet')
    proto_string_dir = os.path.join(output_path, 'protocols/strings')
    proto_pcap_dir = os.path.join(output_path, 'protocols/pcaps')
    proto_values = os.path.join(output_path, 'protocols/values')

    results = {
        'flows': flows,
        'ndpi_summary': ndpi_summary,
        'ip_rep': ip_rep,
        'proto_string_dir': proto_string_dir,
        'proto_pcap_dir': proto_pcap_dir,
        'proto_values': proto_values
    }

    return results


def process_ndpi_summary(pcap_stats):
    sections = {}

    if not pcap_stats:
        return sections

    with open(pcap_stats, "r") as infile:
        stats = infile.read()

    header = None  # To hold the current section heading
    for line in stats.split("\n"):
        if not any(line.startswith(word) for word in ["Using", "Reading", "Running", "'", "*", "-"]):
            if line:
                if line.startswith("\t"):  # Item belongs to the current header
                    # Remove extra spaces and split by the first colon
                    key_value_pair = line.strip().split(": ", 1)
                    if len(key_value_pair) == 2:  # Properly formatted line with a key and value
                        key, value = key_value_pair
                        sections[header].append({'key': key, 'value': value})
                else:  # This is a header line
                    header = line.strip().replace(":", "")
                    sections[header] = []

    return sections


def launch_dashboard():
    additional_templates = os.path.join(os.path.dirname(__file__), "templates")
    app = build_app(reaper_on=False, additional_templates=additional_templates)

    @app.route('/static/<path:filename>')
    def custom_static(filename):
        return send_from_directory(config.CUSTOM_STATIC_PATH, filename)

    @app.route("/", methods=["GET", "POST"])
    def index():
        return render_template("index.html")


    @app.route("/pcaps", methods=["GET"])
    def pcaps():
        pcaps = [
            {"id": id, "filename": f}
            for id, f in enumerate(os.listdir(config.UPLOAD_FOLDER), 1)
            if any(f.strip().endswith(ext) for ext in config.ALLOWED_EXTENSIONS)
        ]

        for pcap in pcaps:
            pcap['outdir'] = os.path.join(config.OUTPUT_DIR, pcap['filename'].replace('.pcap', ''))
        print(f"PCAPS: {pcaps}")

        context = {
            "pcaps": pcaps
        }

        return render_template("pcaps.html", **context)


    @app.route("/upload", methods=["POST"])
    def upload_file():
        if "file" not in request.files:
            flash("No file part")
            return redirect(request.url)
        file = request.files["file"]
        if file.filename == "":
            flash("No selected file")
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(config.UPLOAD_FOLDER, filename))
            flash("File successfully uploaded")
            return redirect(url_for("pcaps"))
        else:
            flash("Invalid file type")
            return redirect(url_for("pcaps"))


    @app.route("/download/<filename>", methods=["GET"])
    def download_file(filename):
        return send_file(os.path.join(config.UPLOAD_DIR, filename), as_attachment=True)


    @app.route("/analyze/<filename>", methods=["GET"])
    def analyze_file(filename):
        # create output directory
        output_path = os.path.join(config.OUTPUT_DIR, filename.replace('.pcap', ''))
        os.makedirs(output_path, exist_ok=True)
        # create "task_created.txt" file to indicate that the task has been created
        with open(os.path.join(output_path, 'task_created.txt'), 'w') as f:
            f.write("Task created")

        process = Process(target=run_luigi_task_in_subprocess, args=(filename,))
        process.start()

        message = {"message": f"Analysis queued for {escape(filename)}"}
        return jsonify(message)

    @app.route('/status/<filename>')
    def get_status(filename):
        # Assume a function `check_task_status` determines if `filename` has been analyzed
        analyzed = check_task_status(filename)
        return jsonify({'analyzed': analyzed})

    @app.route('/summary/<filename>')
    def summary(filename):
        output_files = get_output_files(filename)

        summary = process_ndpi_summary(output_files.get('ndpi_summary', None))

        return render_template("summary.html", summary=summary, filename=filename)

    @app.route('/indicators/<filename>')
    def indicators(filename):
        indicator_parquet = get_output_files(filename).get('ip_rep', None)
        df = pd.read_parquet(indicator_parquet)

        # profile = ProfileReport(df, title=f'Indicator Report for {filename}', explorative=True)
        # profile_html = profile.to_html()
        #
        # return render_template_string(profile_html)

        cleanup("1")
        instance = startup(data_id="1", data=df)
        return redirect(f"/dtale/main/{instance._data_id}", code=302)

    @app.route('/flows/<filename>')
    def flows(filename):
        flows_parquet = get_output_files(filename).get('flows', None)
        df = pd.read_parquet(flows_parquet)

        cleanup("1")
        instance = startup(data_id="1", data=df)
        return redirect(f"/dtale/main/{instance._data_id}", code=302)

    @app.route('/protocols/<filename>')
    def protocols(filename):
        proto_values = get_output_files(filename).get('proto_values', None)
        df = pd.read_parquet(os.path.join(proto_values, 'dnp3_point_values.parquet'))

        cleanup("1")
        instance = startup(data_id="1", data=df)
        return redirect(f"/dtale/main/{instance._data_id}", code=302)

    @app.route('/luigi')
    def luigi_iframe():
        return render_template("luigi_iframe.html")


    app.run(debug=True, port=config.DASH_PORT)


if __name__ == "__main__":
    launch_dashboard()

import os
import glob
import pandas as pd
import luigi
from multiprocessing import Process
from dtale.app import build_app
from dtale.global_state import cleanup
from dtale.views import startup
from flask import (
    request,
    render_template,
    redirect,
    url_for,
    flash,
    jsonify,
    send_file,
    send_from_directory,
)
from markupsafe import escape
from pprint import pprint
from werkzeug.utils import secure_filename

from tpahelper.config import config
from tpahelper.analyze_pcap import AllTasks

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

    @app.route("/download_proto_pcap/<filename>/<protocol>", methods=["GET"])
    def download_proto_pcap(filename, protocol):
        return send_file(os.path.join(config.OUTPUT_DIR, filename.replace('.pcap', ''),
                                      'protocols', 'pcaps', f"{filename}_{protocol}.pcap"), as_attachment=True)

    @app.route("/luigi", methods=["GET"])
    def luigi():
        # redirect to the luigi task status page
        return redirect(url_for("luigi_iframe"))

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
        analyzed = check_task_status(filename)
        return jsonify({'analyzed': analyzed})

    @app.route('/summary/<filename>')
    def summary(filename):
        output_files = get_output_files(filename)

        summary_data = process_ndpi_summary(output_files.get('ndpi_summary', None))

        return render_template("summary.html", summary=summary_data, filename=filename)

    @app.route('/indicators/<filename>')
    def indicators(filename):
        indicator_parquet = get_output_files(filename).get('ip_rep', None)
        df = pd.read_parquet(indicator_parquet)

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
        strings_file_path = get_output_files(filename).get('proto_string_dir', None)
        pcap_file_path = get_output_files(filename).get('proto_pcap_dir', None)
        values_file_path = get_output_files(filename).get('proto_values', None)

        # Get list of strings_files
        strings_files = glob.glob(strings_file_path + '/*.txt')
        print(f"Strings path: {strings_file_path}")
        print(f"Strings files: {strings_files}")

        # Get list of pcap_files
        pcap_files = glob.glob(pcap_file_path + '/*.pcap')
        print(f"PCAP path: {pcap_file_path}")
        print(f"PCAP files: {pcap_files}")

        # Get list of values_files
        values_files = glob.glob(values_file_path + '/*.parquet')
        print(f"Values path: {values_file_path}")
        print(f"Values files: {values_files}")

        protocols = set((os.path.basename(f).split('/')[-1]).split('_')[0]
                        for f in strings_files
                        if 'complete' not in f)

        protocol_data = []
        for protocol in protocols:
            pcap_file = os.path.join(pcap_file_path, f"{filename}_{protocol}.pcap")
            if not os.path.exists(pcap_file):
                pcap_file = None

            strings_file = os.path.join(strings_file_path, f"{protocol}_strings.txt")
            if not os.path.exists(strings_file):
                strings_file = None

            values_file = os.path.join(values_file_path, f"{protocol}_values.parquet")
            if not os.path.exists(values_file):
                values_file = None

            protocol_data.append({
                'protocol': protocol,
                'pcap_file': pcap_file,
                'strings_file': strings_file,
                'values_file': values_file
            })

        pprint(protocol_data)

        return render_template("protocols.html", protocol_data=protocol_data, filename=filename)

    @app.route('/strings/<filename>/<protocol>')
    def strings(filename, protocol):
        strings = os.path.join(get_output_files(filename).get('proto_string_dir', None), f"{protocol}_strings.txt")
        with open(strings, "r") as infile:
            data = infile.readlines()

        return render_template("strings.html", data=data, filename=filename, protocol=protocol)

    @app.route('/values/<filename>/<protocol>')
    def values(filename, protocol):
        values = os.path.join(get_output_files(filename).get('proto_values', None), f"{protocol}_values.parquet")
        df = pd.read_parquet(values)

        cleanup("1")
        instance = startup(data_id="1", data=df)
        return redirect(f"/dtale/main/{instance._data_id}", code=302)

    @app.route('/luigi')
    def luigi_iframe():
        return render_template("luigi_iframe.html")

    app.run(port=config.DASH_PORT, debug=True)


if __name__ == "__main__":
    launch_dashboard()

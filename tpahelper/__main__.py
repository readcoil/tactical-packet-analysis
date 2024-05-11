import os
import subprocess
import signal
from loguru import logger
from tpahelper.config import config
from tpahelper.dashboard.app import launch_dashboard

luigid_process = None


@logger.catch
def start_luigid():
    global luigid_process
    luigid_process = subprocess.Popen(["luigid",
                                       "--address", "localhost",
                                       "--port", str(config.LUIGI_PORT),
                                       "--logdir", config.LOG_DIR,
                                       "--state-path", config.STATE_DIR])


@logger.catch
def stop_luigid():
    global luigid_process
    if luigid_process:
        luigid_process.terminate()
        luigid_process.wait()


@logger.catch
def signal_handler(sig, frame):
    stop_luigid()
    exit(0)


@logger.catch
def main():
    # Create log and state dirs
    os.makedirs(config.LOG_DIR, exist_ok=True)
    os.makedirs(config.STATE_DIR, exist_ok=True)

    # Start luigid
    start_luigid()

    # Register signal handler for SIGINT (Ctrl+C)
    signal.signal(signal.SIGINT, signal_handler)

    launch_dashboard()
    # app.run(debug=True, port=config.DASH_PORT)


if __name__ == "__main__":

    main()
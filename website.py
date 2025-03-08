import os
import subprocess
from flask import Flask, render_template_string, request

app = Flask(__name__)
current_dir = os.path.dirname(os.path.abspath(__file__))

def run_script(script_name, args=[]):
    """
    Run a Python script located in the same directory as this script.
    The external script is invoked with 'python3' and any additional arguments.
    Returns the standard output, or an error message if execution fails.
    """
    script_path = os.path.join(current_dir, script_name)
    command = ["python3", script_path] + args
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        return f"Error: {e.stderr}"

@app.route("/")
def home():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>PurpleTool</title>
      <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
      <style>
        /* Purple theme colors */
        :root {
          --purple-primary: #6f42c1;
          --purple-dark: #5a379e;
          --purple-light: #8e6ac8;
          --text-color: #ffffff;
        }
        body {
          background-color: #f8f9fa;
        }
        .navbar {
          background-color: var(--purple-primary);
        }
        .navbar-brand, .navbar-nav .nav-link {
          color: var(--text-color) !important;
        }
        h1, h2, h3 {
          color: var(--purple-dark);
        }
        /* Primary button style */
        .btn-primary {
          background-color: var(--purple-primary);
          border-color: var(--purple-primary);
        }
        .btn-primary:hover {
          background-color: var(--purple-dark);
          border-color: var(--purple-dark);
        }
        /* Custom purple accents for secondary actions */
        .btn-secondary {
          background-color: var(--purple-light);
          border-color: var(--purple-light);
          color: var(--text-color);
        }
        .btn-secondary:hover {
          background-color: var(--purple-primary);
          border-color: var(--purple-primary);
        }
        /* Schedule and CVE buttons with purple accents */
        .btn-schedule {
          background-color: var(--purple-primary);
          border-color: var(--purple-primary);
          color: var(--text-color);
        }
        .btn-schedule:hover {
          background-color: var(--purple-dark);
          border-color: var(--purple-dark);
        }
      </style>
    </head>
    <body>
      <nav class="navbar navbar-expand-lg">
        <a class="navbar-brand" href="/">PurpleTool</a>
      </nav>
      <div class="container mt-4">
        <h1 class="mb-3">PurpleTool</h1>
        <p class="lead">An All-In-One Tool for Attacking and Defending</p>
        <hr>
        <div class="row">
          <!-- Scan a Website -->
          <div class="col-md-6">
            <h3>Scan a Website</h3>
            <form action="/scan" method="post">
              <div class="form-group">
                <label for="target">Website or IP:</label>
                <input type="text" class="form-control" id="target" name="target" required>
              </div>
              <button type="submit" class="btn btn-primary">Scan</button>
            </form>
          </div>
          <!-- Import a Scan (modeled after Get Latest CVEs) -->
          <div class="col-md-6">
            <h3>Import a Scan</h3>
            <div class="form-row">
              <div class="col-md-6 mb-2">
                <form action="/import_scan" method="post">
                  <div class="form-group">
                    <label for="filepath_import">File Path:</label>
                    <input type="text" class="form-control" id="filepath_import" name="filepath" placeholder="Path to scan" required>
                  </div>
                  <button type="submit" class="btn btn-schedule btn-block">Import</button>
                </form>
              </div>
              <div class="col-md-6">
                <form action="/compare" method="post">
                  <button type="submit" class="btn btn-schedule btn-block" style="height: 150px;">Compare</button>
                </form>
              </div>
            </div>
          </div>
        </div>
        <div class="row mt-4">
          <!-- Schedule Scan -->
          <div class="col-md-6">
            <h3>Schedule Scan</h3>
            <form action="/schedule_scan" method="post">
              <div class="row">
                <div class="col-md-6">
                  <div class="form-group">
                    <label for="target_schedule">Website or IP:</label>
                    <input type="text" class="form-control" id="target_schedule" name="target" placeholder="e.g., example.com or 192.168.1.1" required>
                  </div>
                </div>
                <div class="col-md-6">
                  <div class="form-group">
                    <label for="time">Time (HH:MM):</label>
                    <input type="text" class="form-control" id="time" name="time" placeholder="e.g., 23:59" required>
                  </div>
                </div>
              </div>
              <button type="submit" class="btn btn-schedule btn-block">Schedule</button>
            </form>
          </div>
          <!-- Get Latest CVEs -->
          <div class="col-md-6">
            <h3>Get Latest CVEs</h3>
            <div class="form-row">
              <div class="col-md-6 mb-2">
                <form action="/get_cves_scheduled" method="post">
                  <div class="form-group">
                    <label for="cve_time">Time (HH:MM):</label>
                    <input type="text" class="form-control" id="cve_time" name="time" placeholder="e.g., 23:59" required>
                  </div>
                  <button type="submit" class="btn btn-schedule btn-block">Schedule CVEs</button>
                </form>
              </div>
              <div class="col-md-6">
                <form action="/get_cves_instant" method="post">
                  <button type="submit" class="btn btn-schedule btn-block" style="height: 150px;">Instant CVEs</button>
                </form>
              </div>
            </div>
          </div>
        </div>
      </div>
    </body>
    </html>
    """
    return render_template_string(html)

@app.route("/scan", methods=["POST"])
def scan():
    target = request.form.get("target")
    scan_output = run_script("scan.py", [target])
    
    # Read outputs/webappAUDIT.txt
    try:
        audit_file_path = os.path.join(current_dir, "outputs", "webappAUDIT.txt")
        with open(audit_file_path, "r") as f:
            webapp_audit_content = f.read()
    except Exception as e:
        webapp_audit_content = f"Error reading file: {e}"
    
    # Read outputs/exploitCVE_details.txt
    try:
        exploit_file_path = os.path.join(current_dir, "outputs", "exploitCVE_details.txt")
        with open(exploit_file_path, "r") as f:
            exploit_cve_details_content = f.read()
    except Exception as e:
        exploit_cve_details_content = f"Error reading file: {e}"
    
    output_html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>Scan Results</title>
      <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
      <style>
        body {{ background-color: #f8f9fa; }}
        h2 {{ color: #5a379e; }}
      </style>
    </head>
    <body>
      <div class="container mt-4">
        <h2>Scan Results for {target}</h2>
        <h3>Webapp Audit Details</h3>
        <pre>{webapp_audit_content}</pre>
        <h3>Exploit CVE Details</h3>
        <pre>{exploit_cve_details_content}</pre>
        <a href="/" class="btn btn-secondary">Back to Home</a>
      </div>
    </body>
    </html>
    """
    return render_template_string(output_html)


@app.route("/import_scan", methods=["POST"])
def import_scan():
    filepath = request.form.get("filepath")
    # Run the external script details_imported.py with the provided filepath.
    details_output = run_script("details_imported.py", [filepath])
    
    # Read the file output from outputs/exploitCVE_details_imported.txt.
    try:
        file_path = os.path.join(current_dir, "outputs", "exploitCVE_details_imported.txt")
        with open(file_path, "r") as f:
            file_content = f.read()
    except Exception as e:
        file_content = f"Error reading file: {e}"
    
    # If the file path ends with '.nessus', set a message to display.
    message = ""
    if filepath.lower().endswith(".nessus"):
        message = f"Check {filepath}/result for .nessus file details."
    
    output_html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>Imported Scan Results</title>
      <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
      <style>
        body {{ background-color: #f8f9fa; }}
        h2 {{ color: #5a379e; }}
      </style>
    </head>
    <body>
      <div class="container mt-4">
        <h2>Imported Scan Results for {filepath}</h2>
        {f"<h3>Message</h3><pre>{message}</pre>" if message else ""}
        <h3>Exploit CVE Details Imported</h3>
        <pre>{file_content}</pre>
        <a href="/" class="btn btn-secondary">Back to Home</a>
      </div>
    </body>
    </html>
    """
    return render_template_string(output_html)



@app.route("/compare", methods=["POST"])
def compare():
    compare_output = run_script("compare.py", [])
    try:
        file_path = os.path.join(current_dir, "outputs", "compare.txt")
        with open(file_path, "r") as f:
            file_compare_output = f.read()
    except Exception as e:
        file_compare_output = f"Error reading file: {e}"
    output_html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>Comparison Results</title>
      <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
      <style>
        body {{ background-color: #f8f9fa; }}
        h2 {{ color: #5a379e; }}
      </style>
    </head>
    <body>
      <div class="container mt-4">
        <h2>Comparison Results</h2>
        <h3>Script Output</h3>
        <pre>{compare_output}</pre>
        <h3>File Output</h3>
        <pre>{file_compare_output}</pre>
        <a href="/" class="btn btn-secondary">Back to Home</a>
      </div>
    </body>
    </html>
    """
    return render_template_string(output_html)


@app.route("/schedule_scan", methods=["POST"])
def schedule_scan():
    time_str = request.form.get("time")
    target = request.form.get("target")
    scan_script_path = os.path.join(current_dir, "scan_scheduled.py")
    schedule_output = run_script("schedule.py", [scan_script_path, time_str, target])
    output_html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>Schedule Scan</title>
      <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
      <style>
        body {{ background-color: #f8f9fa; }}
        h2 {{ color: #5a379e; }}
      </style>
    </head>
    <body>
      <div class="container mt-4">
        <h2>Scheduled Scan at {time_str} for {target}</h2>
        <pre>{schedule_output}</pre>
        <a href="/" class="btn btn-secondary">Back to Home</a>
      </div>
    </body>
    </html>
    """
    return render_template_string(output_html)

@app.route("/get_cves_instant", methods=["POST"])
def get_cves_instant():
    instant_output = run_script("newCVE.py", [])
    try:
        file_path = os.path.join(current_dir, "outputs", "newCVE.txt")
        with open(file_path, "r") as f:
            newcve_file_output = f.read()
    except Exception as e:
        newcve_file_output = f"Error reading file: {e}"
    output_html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>Latest CVEs Instantly</title>
      <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
      <style>
        body {{ background-color: #f8f9fa; }}
        h2 {{ color: #5a379e; }}
      </style>
    </head>
    <body>
      <div class="container mt-4">
        <h2>Latest CVEs (Instant)</h2>
        <pre>{instant_output}</pre>
        <h2>New CVE File Output</h2>
        <pre>{newcve_file_output}</pre>
        <a href="/" class="btn btn-secondary">Back to Home</a>
      </div>
    </body>
    </html>
    """
    return render_template_string(output_html)


@app.route("/get_cves_scheduled", methods=["POST"])
def get_cves_scheduled():
    cve_time = request.form.get("time")
    scheduled_output = run_script("scheduleCVE.py", ["newCVE_scheduled.py", cve_time])
    output_html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>Scheduled Latest CVEs</title>
      <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
      <style>
        body {{ background-color: #f8f9fa; }}
        h2 {{ color: #5a379e; }}
      </style>
    </head>
    <body>
      <div class="container mt-4">
        <h2>Scheduled Latest CVEs at {cve_time}</h2>
        <pre>{scheduled_output}</pre>
        <a href="/" class="btn btn-secondary">Back to Home</a>
      </div>
    </body>
    </html>
    """
    return render_template_string(output_html)

if __name__ == "__main__":
    app.run(debug=True)

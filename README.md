# Automatically Download and Analyze Log Files from Remote Machines

This application is designed to collect and analyze logs from remote machines hosted on Amazon Web Services (AWS) and other cloud hosting services.

**Note**: This application was specifically designed for use with Pastel Network's log files. However, it can be easily adapted to work with any log files by modifying the parsing functions, data models, and specifying the location and names of the log files to be downloaded. It is compatible with log files stored in a standard format, where each entry is on a separate line and contains a timestamp, a log level, and a message. The application has been tested with log files several gigabytes in size from dozens of machines and can process all of it in minutes. It is designed for Ubuntu 22.04+, but can be adapted for other Linux distributions.

![Demo Screenshot:](https://raw.githubusercontent.com/Dicklesworthstone/automatic_log_collector_and_analyzer/main/demo_screenshot.png)

## Customization

To adapt this application for your own use case, refer to the included sample log files and compare them to the parsing functions in the code. You can also modify the data models to store log entries as desired.

## Features

The application consists of various Python scripts that perform the following functions:

* **Connect to Remote Machines**: Using the boto3 library for AWS instances and an Ansible inventory file for non-AWS instances, the application establishes SSH connections to each remote machine.
* **Download and Parse Log Files**: Downloads specified log files from each remote machine and parses them. The parsed log entries are then queued for database insertion.
* **Insert Log Entries into Database**: Uses SQLAlchemy to insert the parsed log entries from the queue into an SQLite database.
* **Process and Analyze Log Entries**: Processes and analyzes log entries stored in the database, offering functions to find error entries and create views of aggregated data based on specified criteria.
* **Generate Network Activity Data**: Fetches and processes network activity data from each remote machine.
* **Expose Database via Web App using Datasette**: Once the database is generated, it can be shared over the web using Datasette.

## Compatibility

The tool is compatible with both AWS-hosted instances and any list of Linux instances stored in a standard Ansible inventory file with the following structure:

```yaml
all:
  vars:
    ansible_connection: ssh
    ansible_user: ubuntu
    ansible_ssh_private_key_file: /path/to/ssh/key/file.pem
  hosts:
    MyCoolMachine01:
      ansible_host: 1.2.3.41
    MyCoolMachine02:
      ansible_host: 1.2.3.19
```

(Both can be used seamlessly.)

## Warning

To simplify the code, the tool is designed to delete all downloaded log files and generated databases each time it runs. Consequently, this can consume significant bandwidth depending on your log files' size. However, the design's high level of parallel processing and concurrency allows it to run quickly, even when connecting to dozens of remote machines and downloading hundreds of log files.

## Usage

Designed for Ubuntu 22.04+, first install the requirements:

```bash
python3 -m venv venv
source venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install wheel
pip install -r requirements.txt
```

You will also need to install Redis:

```bash
sudo apt install redis -y
```

And install Datasette to expose the results as a website:

```bash
sudo apt install pipx -y && pipx ensurepath && pipx install datasette
```

To run the application every 30 minutes as a cron job, execute:

```bash
crontab -e
```

And add the following line:

```bash
*/30 * * * * . $HOME/.profile; /home/ubuntu/automatic_log_collector_and_analyzer/venv/bin/python /home/ubuntu/automatic_log_collector_and_analyzer/automatic_log_collector_and_analyzer.py >> /home/ubuntu/automatic_log_collector_and_analyzer/log_$(date +\%Y-\%m-\%dT\%H_\%M_\%S).log 2>&1
```
---

Thanks for your interest in my open-source project! I hope you find it useful. You might also find my commercial web apps useful, and I would really appreciate it if you checked them out:

**[YoutubeTranscriptOptimizer.com](https://youtubetranscriptoptimizer.com)** makes it really quick and easy to paste in a YouTube video URL and have it automatically generate not just a really accurate direct transcription, but also a super polished and beautifully formatted written document that can be used independently of the video.

The document basically sticks to the same material as discussed in the video, but it sounds much more like a real piece of writing and not just a transcript. It also lets you optionally generate quizzes based on the contents of the document, which can be either multiple choice or short-answer quizzes, and the multiple choice quizzes get turned into interactive HTML files that can be hosted and easily shared, where you can actually take the quiz and it will grade your answers and score the quiz for you.

**[FixMyDocuments.com](https://fixmydocuments.com/)** lets you submit any kind of document— PDFs (including scanned PDFs that require OCR), MS Word and Powerpoint files, images, audio files (mp3, m4a, etc.) —and turn them into highly optimized versions in nice markdown formatting, from which HTML and PDF versions are automatically generated. Once converted, you can also edit them directly in the site using the built-in markdown editor, where it saves a running revision history and regenerates the PDF/HTML versions.

In addition to just getting the optimized version of the document, you can also generate many other kinds of "derived documents" from the original: interactive multiple-choice quizzes that you can actually take and get graded on; slick looking presentation slides as PDF or HTML (using LaTeX and Reveal.js), an in-depth summary, a concept mind map (using Mermaid diagrams) and outline, custom lesson plans where you can select your target audience, a readability analysis and grade-level versions of your original document (good for simplifying concepts for students), Anki Flashcards that you can import directly into the Anki app or use on the site in a nice interface, and more.

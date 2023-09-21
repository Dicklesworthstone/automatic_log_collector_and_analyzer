# Automatically Download and Analyze Log Files from Remote Machines

This application is designed to collect and analyze logs from remote machines that are hosted on Amazon Web Services (AWS) and on other cloud hosting services.

NOTE: This was specifically designed to be used with Pastel Network's particular log files, but it can be easily adapted to work with any log files by modifying the parsing functions and the data models, and specifying the location and names of the log files to be downloaded. It is designed to work with any log files that are stored in a standard format, with each log entry on a separate line, and with each log entry containing a timestamp, a log level, and a message. It has been tested using log files that are several gigabytes in size, and it can process them in a matter of minutes. Designed to work under Ubuntu 22.04+ but can be easily adapted to work with any Linux distribution.

To customize to your own application, check out the included sample log files and compare them to the parsing functions in the code. You can also modify the data models to store the log entries in any way you want. The application is designed to be flexible and scalable, and it can be easily adapted to work with any log files.

The application consists of various Python scripts that perform the following functions:

* Connect to Remote Machines: Using the boto3 library for AWS instances and an Ansible inventory file for non-AWS instances, the application establishes SSH connections to each remote machine.

* Download and Parse Log Files: It downloads specified log files from each remote machine and parses them. The parsed log entries are then added to a queue for database insertion.

* Insert Log Entries into Database: The application uses SQLAlchemy to insert the parsed log entries from the queue into an SQLite database.

* Process and Analyze Log Entries: It processes and analyzes the log entries stored in the database. It provides functions to find error entries and to create views of aggregated data based on specified criteria.

* Generate Network Activity Data: The application also fetches and processes network activity data from each remote machine.

* Expose the Generated Database as a Web App using Datasette: Once the database has been created from the log files, it can be easily shared with users over the web, where they can sort and filter it using Datasette.

The application is designed to be flexible and scalable. It uses multithreading to efficiently process log entries from multiple remote machines concurrently. It is also adaptable to handle remote machines on any cloud hosting service, as long as the details of the machines are provided in an Ansible inventory file.

Note: This tool is designed to work with both AWS hosted instances (in which case you simply have to specify the instance name prefix and it will automatically retrieve all relevant instance IDs and other machine information such as instance name and public IP address using the boto3 library), OR you can use it with any list of linux instances stored in a standard ansible inventory file with the following structure:

```
all:
  vars:
    ansible_connection: ssh
    ansible_user: ubuntu
    ansible_ssh_private_key_file: /path/to/ssh/key/file.pem
  hosts:
    MyCoolMachine01:
      ansible_host: 1.2.3.41
    MyCoolMachine02:
      ansible_host: 1.2.3.41.19
```

(You can also use a mixture of both seamlessly). 

# Warning:
To simplify the code, the tools is designed to delete all downloaded log files and that generated databases each time it is run; it then downloads all log files from scratch from each remote machine in full and reconstructs the database.

As a result, this can end up using a lot of bandwidth depending on the size of your log files. However, because of the extreme amount of parallel processing and concurrency in the design, it still can run quite quickly (in under a few minutes) while connecting to dozens of remote machines and downloading hundreds of log files totaling gigabytes of storage.

# To Use:

This is designed to run on Ubuntu 22.04+. First, install the requirements:

```
python3 -m venv venv
source venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install wheel
pip install -r requirements.txt
```

You will also need to install Redis:

```
sudo apt-get install redis
```

And you will need to install Datasette to expose the results as a website:

```
pip install datasette
```

To run every 30 minutes as a cron job:

```
crontab -e
```

Add the following line:

```
*/15 * * * * . $HOME/.profile; /home/ubuntu/automatic_log_collector_and_analyzer/venv/bin/python /home/ubuntu/automatic_log_collector_and_analyzer/automatic_log_collector_and_analyzer.py >> /home/ubuntu/automatic_log_collector_and_analyzer/log_$(date +\%Y-\%m-\%dT\%H_\%M_\%S).log 2>&1
```


import time
import os
import sys
import subprocess
import mmap
import glob
import re
import hashlib
import json
import signal
import sqlite3
import shlex
import shutil
import threading
from functools import lru_cache
import datetime as dt
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from multiprocessing import Pool, Manager
from typing import List, Dict
from tqdm import tqdm
import boto3
import paramiko
import sqlalchemy as sa
from sqlalchemy import and_, Column, Integer, JSON, ForeignKey
from sqlalchemy.orm import relationship, sessionmaker, Session
from sqlalchemy.exc import OperationalError, IntegrityError
from sqlalchemy.sql.expression import or_
import redis
import cProfile
import pstats
import pandas as pd
import concurrent.futures
from collections import Counter
import yaml
from decouple import config

SSH_TIMEOUT_SECONDS = config("SSH_TIMEOUT_SECONDS", cast=int)
BASE_PATH = config("BASE_PATH", cast=str)

lock_file = "automatic_log_collector_and_analyzer.lock"
if os.path.exists(lock_file):
    print("Lock file exists, another instance of the script is running. Exiting.")
    sys.exit()
open(lock_file, 'w').close()
Base = sa.orm.declarative_base()

# Prerequisites under Ubuntu 20+:
# sudo apt update && sudo apt install redis pipx -y && pipx ensurepath && pipx install datasette

class LogEntry(Base):
    __tablename__ = 'log_entries'
    id = sa.Column(sa.Integer, primary_key=True)
    hash_id = sa.Column(sa.String, index=True)
    instance_id = sa.Column(sa.String)
    machine_name = sa.Column(sa.String, index=True)
    public_ip = sa.Column(sa.String, index=True)
    log_file_source = sa.Column(sa.String, index=True)
    timestamp = sa.Column(sa.DateTime)
    message = sa.Column(sa.String)


class SNStatus(Base):
    __tablename__ = 'sn_status'
    id = sa.Column(sa.Integer, primary_key=True)
    public_ip = sa.Column(sa.String)
    instance_name = sa.Column(sa.String)
    datetime_of_data = sa.Column(sa.String)
    version = sa.Column(sa.Integer)
    protocolversion = sa.Column(sa.Integer)
    walletversion = sa.Column(sa.Integer)
    chain = sa.Column(sa.String)
    balance = sa.Column(sa.Float)
    blocks = sa.Column(sa.Integer)
    timeoffset = sa.Column(sa.Integer)
    connections = sa.Column(sa.Integer)
    proxy = sa.Column(sa.String)
    difficulty = sa.Column(sa.Float)
    testnet = sa.Column(sa.Boolean)  # Add this line
    keypoololdest = sa.Column(sa.Integer)
    keypoolsize = sa.Column(sa.Integer)
    paytxfee = sa.Column(sa.Float)
    relayfee = sa.Column(sa.Float)
    errors = sa.Column(sa.String)
    masternode_collateral_txid_and_outpoint = sa.Column(sa.String)
    masternode_collateral_address = sa.Column(sa.String)
    sn_pastelid_pubkey = sa.Column(sa.String)
    sn_alias = sa.Column(sa.String)
    sn_status = sa.Column(sa.String)
    def to_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}


class SNMasternodeStatus(Base):
    __tablename__ = 'sn_masternode_status'
    public_ip = sa.Column(sa.String)
    instance_name = sa.Column(sa.String)
    datetime_of_data = sa.Column(sa.String)    
    id = sa.Column(sa.Integer, primary_key=True)
    masternode_collateral_txid_and_outpoint = sa.Column(sa.String)
    masternode_status_message = sa.Column(sa.String)
    protocol_version = sa.Column(sa.String)
    masternode_collateral_address = sa.Column(sa.String)
    datetime_last_seen = sa.Column(sa.String)
    active_seconds = sa.Column(sa.String)
    datetime_last_paid = sa.Column(sa.String)
    last_paid_blockheight = sa.Column(sa.String)
    ip_address_and_port = sa.Column(sa.String)
    rank_as_of_block_height = Column(sa.Integer)
    masternode_rank = Column(sa.Integer)
    sn_pastelid_pubkey = Column(sa.String)
    def to_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}


class SNNetworkActivityNetstat(Base):
    __tablename__ = 'sn_network_activity_netstat'
    id = sa.Column(sa.Integer, primary_key=True)
    public_ip = sa.Column(sa.String)
    instance_name = sa.Column(sa.String)
    datetime_of_data = sa.Column(sa.String)
    netstat__proto = sa.Column(sa.String)
    netstat__recv_q = sa.Column(sa.Integer)
    netstat__send_q = sa.Column(sa.Integer)
    netstat__local_address = sa.Column(sa.String)
    netstat__foreign_address = sa.Column(sa.String)
    netstat__state = sa.Column(sa.String)
    netstat__pid_program_name = sa.Column(sa.String)
    def to_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}


class SNNetworkActivityLSOF(Base):
    __tablename__ = 'sn_network_activity_lsof'
    id = sa.Column(sa.Integer, primary_key=True)
    public_ip = sa.Column(sa.String)
    instance_name = sa.Column(sa.String)
    datetime_of_data = sa.Column(sa.String)
    lsof__command = sa.Column(sa.String)
    lsof__pid = sa.Column(sa.Integer)
    lsof__user = sa.Column(sa.String)
    lsof__fd = sa.Column(sa.String)
    lsof__type = sa.Column(sa.String)
    lsof__device = sa.Column(sa.String)
    lsof__size_off = sa.Column(sa.String)
    lsof__node = sa.Column(sa.String)
    lsof__name = sa.Column(sa.String)
    def to_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}


class SNNetworkActivitySS(Base):
    __tablename__ = 'sn_network_activity_ss'
    id = sa.Column(sa.Integer, primary_key=True)
    public_ip = sa.Column(sa.String)
    instance_name = sa.Column(sa.String)
    datetime_of_data = sa.Column(sa.String)
    ss__state = sa.Column(sa.String)
    ss__recv_q = sa.Column(sa.Integer)
    ss__send_q = sa.Column(sa.Integer)
    ss__local_address_port = sa.Column(sa.String)
    ss__peer_address_port = sa.Column(sa.String)
    ss__process = sa.Column(sa.String)
    def to_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}


class NodeHealthChecks(Base):
    __tablename__ = 'node_health_checks'
    id = Column(Integer, primary_key=True)
    missing_status_responses = Column(JSON) # JSON type is used for list of strings
    out_of_sync_nodes = Column(JSON) # JSON type is used for complex nested structure
    nodes_with_zero_connections = Column(JSON) # JSON type is used for list of strings
    

class NodeMasternodeHealthChecks(Base):
    __tablename__ = 'node_masternode_health_checks'
    id = Column(Integer, primary_key=True)
    masternode_rank_outlier_report_explanations = Column(JSON, nullable=True)
    all_new_start_required = Column(JSON, nullable=True)
    supernodes_reported_to_be_in_new_start_required_mode = Column(JSON, nullable=True)
        

class EntriesBeforeAndAfterPanics(Base):
    __tablename__ = 'entries_before_and_after_panics'
    id = Column(Integer, primary_key=True)
    log_entry_id = Column(Integer, ForeignKey('log_entries.id'))
    log_entry = relationship("LogEntry")

class MiscErrorEntries(Base):
    __tablename__ = 'misc_error_entries'
    id = Column(Integer, primary_key=True)
    log_entry_id = Column(Integer, ForeignKey('log_entries.id'))
    log_entry = relationship("LogEntry")

def get_instance_name(tags):
    for tag in tags:
        if tag['Key'] == 'Name':
            return tag['Value']
    return None

def get_instances_with_name_prefix(name_prefix, aws_access_key_id, aws_secret_access_key, aws_region):
    ec2 = boto3.resource('ec2', region_name=aws_region, aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)
    instances = ec2.instances.filter(
        Filters=[
            {'Name': 'tag:Name', 'Values': [f'{name_prefix}*']},
            {'Name': 'instance-state-name', 'Values': ['running']}
        ]
    )
    instances = sorted(instances, key=lambda instance: get_instance_name(instance.tags))
    return instances

def get_inventory():
    with open(config("ANSIBLE_INVENTORY_FILE", cast=str), 'r') as f:
        return yaml.safe_load(f)

def get_ssh_key_and_user(instance_name):
    inventory = get_inventory()
    hosts = inventory.get('all', {}).get('hosts', {})
    if instance_name in hosts:
        host_data = hosts[instance_name]
        return host_data.get('ansible_ssh_private_key_file'), inventory['all']['vars'].get('ansible_user', 'ubuntu')
    return None, None

def ssh_connect(ip, user, key_path):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(ip, username=user, key_filename=key_path, timeout=5)
        ssh.close()
        return (True, None)
    except paramiko.AuthenticationException:
        return (False, "Authentication failed.")
    except Exception as e:
        return (False, str(e))

def calculate_hash_id(log_entry):
    hash_content = f"{log_entry['instance_id']}{log_entry['machine_name']}{log_entry['public_ip']}{log_entry['log_file_source']}{log_entry['message']}"
    return hashlib.sha256(hash_content.encode()).hexdigest()

def execute_network_commands_func(command: str) -> str:
    result = subprocess.run(command, shell=True, text=True, capture_output=True)
    return result.stdout

def parse_netstat_output(output: str) -> Dict:
    lines = output.split('\n')[2:]
    records = []
    for line in lines:
        if line:
            fields = line.split()
            record = {
                'netstat__proto': fields[0],
                'netstat__recv_q': int(fields[1]),
                'netstat__send_q': int(fields[2]),
                'netstat__local_address': fields[3],
                'netstat__foreign_address': fields[4],
                'netstat__state': fields[5] if len(fields) > 5 else None,
                'netstat__pid_program_name': fields[6] if len(fields) > 6 else None
            }
            records.append(record)
    return records

def parse_lsof_output(output: str) -> Dict:
    lines = output.split('\n')[1:]
    records = []
    for line in lines:
        if line:
            fields = line.split()
            record = {
                'lsof__command': fields[0],
                'lsof__pid': int(fields[1]),
                'lsof__user': fields[2],
                'lsof__fd': fields[3],
                'lsof__type': fields[4],
                'lsof__device': fields[5],
                'lsof__size_off': fields[6],
                'lsof__node': fields[7],
                'lsof__name': fields[8]
            }
            records.append(record)
    return records

def parse_ss_output(output: str) -> Dict:
    lines = output.split('\n')[1:]
    records = []
    for line in lines:
        if line:
            fields = line.split()
            record = {
                'ss__state': fields[0],
                'ss__recv_q': int(fields[1]),
                'ss__send_q': int(fields[2]),
                'ss__local_address_port': fields[3],
                'ss__peer_address_port': fields[4],
                'ss__process': ' '.join(fields[5:])
            }
            records.append(record)
    return records

def get_sn_network_data(remote_ip, user, key_path, instance_name):
    global engine
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    Session = sessionmaker(bind=engine)
    session = Session()
    try:
        ssh.connect(remote_ip, username=user, key_filename=key_path, timeout=SSH_TIMEOUT_SECONDS)
        commands_and_parsers = [
            ('sudo netstat -tulnp', parse_netstat_output, SNNetworkActivityNetstat),
            ('sudo lsof -i', parse_lsof_output, SNNetworkActivityLSOF),
            ('sudo ss -tnp', parse_ss_output, SNNetworkActivitySS),
        ]
        for command, parser, model in commands_and_parsers:
            stdin, stdout, stderr = ssh.exec_command(command)
            output = stdout.read().decode('utf-8')
            parsed_records = parser(output)
            for record in parsed_records:
                record.update({
                    'public_ip': remote_ip,
                    'instance_name': instance_name,
                    'datetime_of_data': datetime.now().isoformat()
                })
                sn_network_activity = model(**record)
                session.add(sn_network_activity)
        session.commit()
    except Exception as e:
        print(f"Error while getting network data: {str(e)}")
    finally:
        ssh.close()
        session.close()

def download_logs(remote_ip, user, key_path, instance_name, log_files):
    log_files_directory = "downloaded_log_files"
    os.makedirs(log_files_directory, exist_ok=True)
    current_time = dt.datetime.now()
    list_of_local_log_file_names = []
    def is_recently_downloaded(file_name):
        if os.path.exists(file_name):
            file_modification_time = dt.datetime.fromtimestamp(os.path.getmtime(file_name))
            time_difference = current_time - file_modification_time
            return time_difference < dt.timedelta(minutes=5)
        return False
    def download_log_file(log_file, local_file_name, sudo_prefix="sudo ", skip_first_line=False):
        try:
            cat_command = f"{sudo_prefix}cat {log_file}"
            if skip_first_line:
                cat_command = f"{sudo_prefix}tail -n +2 {log_file}"
            subprocess.run(['bash', '-c', f'ssh -i {key_path} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {user}@{remote_ip} "{cat_command}" > {local_file_name}'], check=True)
            print(f"Downloaded log file {log_file} from {instance_name} ({remote_ip}) to {local_file_name}")
        except subprocess.CalledProcessError as e:
            print(f"Error downloading log file {log_file} from {instance_name} ({remote_ip}): {e}")
    with ThreadPoolExecutor() as executor:
        futures = []
        for log_file in log_files:
            local_file_name = os.path.join(log_files_directory, f"{instance_name.replace(' ', '_')}__{remote_ip.replace('.','_')}__{os.path.basename(log_file)}")
            list_of_local_log_file_names += [local_file_name]
            if is_recently_downloaded(local_file_name):
                print(f"Log file {local_file_name} was downloaded within the past 5 minutes, skipping download.")
                continue
            futures.append(executor.submit(download_log_file, log_file, local_file_name))
        remote_journalctl_output = f"/home/{user}/journalctl_output.txt"
        try:
            subprocess.run(["ssh", "-i", key_path, "-o", "StrictHostKeyChecking=no", f"{user}@{remote_ip}", f"sudo journalctl --since '-1 weeks' > {remote_journalctl_output}"], check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error running journalctl command on {instance_name} ({remote_ip}): {e}")
        local_journalctl_file_name = os.path.join(log_files_directory, f"{instance_name.replace(' ', '_')}__{remote_ip.replace('.','_')}__systemd_log.txt")
        list_of_local_log_file_names += [local_journalctl_file_name]
        if not is_recently_downloaded(local_journalctl_file_name):
            futures.append(executor.submit(download_log_file, remote_journalctl_output, local_journalctl_file_name, skip_first_line=True))
        for future in futures:
            future.result()
    print(f"Finished downloading all log files from {instance_name} ({remote_ip})")
    return list_of_local_log_file_names

def check_sn_status(remote_ip, user, key_path, instance_name):
    global engine
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    Session = sessionmaker(bind=engine)
    session = Session()
    output_dict = {'Error': f'Could not connect to instance {instance_name}.'}
    try:
        ssh.connect(remote_ip, username=user, key_filename=key_path, timeout=SSH_TIMEOUT_SECONDS)
        stdin, stdout, stderr = ssh.exec_command('/home/ubuntu/pastel/pastel-cli masternode status')
        mn_status_output = stdout.read().decode('utf-8')
        if mn_status_output:
            mn_status_output_dict = json.loads(mn_status_output)
        else:
            mn_status_output_dict = {}
        print(f"mn_status_output_dict for {instance_name} ({remote_ip}): {mn_status_output_dict}")
        
        stdin, stdout, stderr = ssh.exec_command('/home/ubuntu/pastel/pastel-cli getinfo')
        output = stdout.read().decode('utf-8')
        if output:
            output_dict = json.loads(output)
            output_dict['public_ip'] = remote_ip
            output_dict['instance_name'] = instance_name
            output_dict['datetime_of_data'] = datetime.now().isoformat()
            if len(mn_status_output_dict) > 0:
                output_dict['masternode_collateral_txid_and_outpoint'] = mn_status_output_dict['outpoint']
                output_dict['masternode_collateral_address'] = mn_status_output_dict['payee']
                output_dict['sn_pastelid_pubkey'] = mn_status_output_dict['extKey']
                output_dict['sn_alias'] = mn_status_output_dict['alias']
                output_dict['sn_status'] = mn_status_output_dict['status']
            print(f"output_dict for {instance_name} ({remote_ip}): {output_dict}")
            sn_status = SNStatus(**output_dict)
            session.add(sn_status)
            session.commit()
            print(f"Data collected and inserted for {instance_name} ({remote_ip})")
        else:
            print(f"No output from getinfo command for {instance_name} ({remote_ip})")
    except Exception as e:
        print(f"Error while checking sn status for {instance_name} ({remote_ip}): {str(e)}")
    finally:
        ssh.close()
        session.close()
    return output_dict

def check_sn_masternode_status(remote_ip, user, key_path, instance_name):
    global engine
    cmd1 = '/home/ubuntu/pastel/pastel-cli masternode list full'
    result1 = subprocess.run(['ssh', '-i', key_path, '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null', '-o', f'ConnectTimeout={SSH_TIMEOUT_SECONDS}', f'{user}@{remote_ip}', cmd1], capture_output=True, text=True)
    if len(result1.stdout) > 0:
        data1 = json.loads(result1.stdout)
        cmd2 = '/home/ubuntu/pastel/pastel-cli masternode top'
        result2 = subprocess.run(['ssh', '-i', key_path, '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null','-o', f'ConnectTimeout={SSH_TIMEOUT_SECONDS}', f'{user}@{remote_ip}', cmd2], capture_output=True, text=True)
        data2 = json.loads(result2.stdout)
        rank_as_of_block_height = int(list(data2.keys())[0])
        data2_values = [x for x in list(data2.values())[0]]
        masternode_top_dict = {}
        for current_value in data2_values:
            masternode_collateral_txid_and_outpoint = current_value['outpoint']
            masternode_rank = int(current_value['rank'])
            sn_pastelid_pubkey = current_value['extKey']
            masternode_top_dict[masternode_collateral_txid_and_outpoint] = {'masternode_rank': masternode_rank, 'sn_pastelid_pubkey': sn_pastelid_pubkey, 'rank_as_of_block_height': rank_as_of_block_height}
        cmd3 = '/home/ubuntu/pastel/pastel-cli masternode list extra'
        result3 = subprocess.run(['ssh', '-i', key_path, '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null','-o', f'ConnectTimeout={SSH_TIMEOUT_SECONDS}', f'{user}@{remote_ip}', cmd3], capture_output=True, text=True)
        data3 = json.loads(result3.stdout)
        Session = sessionmaker(bind=engine)
        session = Session()
        combined_masternode_status_dict = {}
        for key, value in data1.items():
            extra = masternode_top_dict.get(key, {})
            if len(extra) > 0:
                sn_pastelid_pubkey = extra.get('sn_pastelid_pubkey')
                masternode_rank = extra.get('masternode_rank')
                rank_as_of_block_height = extra.get('rank_as_of_block_height')
            else:
                extra = data3.get(key, {})
                sn_pastelid_pubkey = extra.get('extKey')
                masternode_rank = -1
                rank_as_of_block_height = -1
            values = value.split()
            masternode_status_message = values[0]
            protocol_version = values[1]
            masternode_collateral_address = values[2]
            datetime_last_seen = values[3]
            active_seconds = values[4]
            datetime_last_paid = values[5]
            last_paid_blockheight = values[6]
            ip_address_and_port = values[7]
            status = SNMasternodeStatus(
                masternode_collateral_txid_and_outpoint=key,
                masternode_status_message=masternode_status_message,
                protocol_version=protocol_version,
                masternode_collateral_address=masternode_collateral_address,
                datetime_last_seen=datetime_last_seen,
                active_seconds=active_seconds,
                datetime_last_paid=datetime_last_paid,
                last_paid_blockheight=last_paid_blockheight,
                ip_address_and_port=ip_address_and_port,
                sn_pastelid_pubkey=sn_pastelid_pubkey,
                masternode_rank = masternode_rank,
                rank_as_of_block_height = rank_as_of_block_height, 
                public_ip=remote_ip,
                instance_name=instance_name,
                datetime_of_data= datetime.now().isoformat(),
            )
            combined_masternode_status_dict[key] = status.to_dict()
            session.add(status)
            session.commit()
        session.close()
    else:
        combined_masternode_status_dict = {'Error': f'Could not connect to instance {instance_name}.'}
    return combined_masternode_status_dict

@lru_cache(maxsize=None)
def get_current_year():
    return datetime.now().year

cnode_pattern = re.compile(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}")
gonode_pattern = re.compile(r"\[.*\]")
dd_service_pattern = re.compile(r"(\d{1,7}) - (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})? \[.*\]")
dd_entry_pattern = re.compile(r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}) - (.*)$')
systemd_pattern = re.compile(r"(\S+)\s(\d+)\s(\d+):(\d+):(\d+)\s(\S+)\s(.*)")

def parse_cnode_log(log_line):
    match = cnode_pattern.search(log_line)
    if match:
        try:
            timestamp = datetime.strptime(match.group(), "%Y-%m-%d %H:%M:%S")
            message = log_line[match.end():].strip()
            return {'timestamp': timestamp, 'message': message}
        except ValueError:
            return None
    return None

def parse_systemd_log(log_line):
    match = systemd_pattern.match(log_line)
    if match:
        log_parts = match.groups()
        timestamp_str = f"{log_parts[0]} {log_parts[1]} {log_parts[2]}:{log_parts[3]}:{log_parts[4]}"
        timestamp = datetime.strptime(timestamp_str, "%b %d %H:%M:%S")
        current_year = get_current_year()
        timestamp = timestamp.replace(year=current_year)
        message = log_parts[6]
        return {'timestamp': timestamp, 'message': message}
    return None

def parse_gonode_log(log_line):
    match = gonode_pattern.search(log_line)
    if match:
        datetime_str = match.group().strip("[]")
        timestamp = datetime.strptime(datetime_str, "%b %d %H:%M:%S.%f")
        current_year = get_current_year()
        timestamp = timestamp.replace(year=current_year)
        message = log_line[match.end():].strip()
        return {'timestamp': timestamp, 'message': message}
    return None

def parse_dd_service_log(log_line, last_timestamp=None):
    match = dd_service_pattern.search(log_line)
    if match:
        if match.group(2) is not None:
            datetime_str = match.group(2).strip("[]")
            timestamp = datetime.strptime(datetime_str, "%Y-%m-%d %H:%M:%S.%f")
        elif last_timestamp is not None:
            timestamp = last_timestamp
        else:
            return None
        message = log_line[match.end():].strip()
        return {'timestamp': timestamp, 'message': message}
    return None

def parse_dd_entry_log(entry_line, last_timestamp=None):
    match = dd_entry_pattern.search(entry_line)
    if match:
        datetime_str = match.group(1)
        message = match.group(2).strip()
        try:
            timestamp = datetime.strptime(datetime_str, "%Y-%m-%d %H:%M:%S.%f")
        except ValueError:
            timestamp = last_timestamp
        return {'timestamp': timestamp, 'message': message}
    return None

def parse_logs(local_file_name: str, instance_id: str, machine_name: str, public_ip: str, log_file_source: str) -> List[Dict]:
    global earliest_date_cutoff
    list_of_ignored_strings = ['sshd[']
    log_entries = []
    if "debug.log" in local_file_name:
        parse_function = parse_cnode_log
    elif ("supernode.log" in local_file_name) or ("hermes.log" in local_file_name):
        parse_function = parse_gonode_log
    elif "dd-service-log.txt" in local_file_name:
        parse_function = parse_dd_service_log
    elif "entry.log" in local_file_name:
        parse_function = parse_dd_entry_log
    elif "systemd_log.txt" in local_file_name:
        parse_function = parse_systemd_log
    else:
        raise ValueError("Unsupported log file format")
    if os.path.getsize(local_file_name) == 0:
        print(f"File '{local_file_name}' is empty. Skipping parsing.")
        return log_entries
    with open(local_file_name, 'r') as f:
        mmapped_file = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        for line in tqdm(iter(mmapped_file.readline, b'')):
            line = line.decode('utf-8')
            try:
                parsed_log = parse_function(line)
                if parsed_log:
                    if len(parsed_log['message']) > 0 and not any(ignored_string in parsed_log['message'] for ignored_string in list_of_ignored_strings):
                        if parsed_log['timestamp'] < earliest_date_cutoff:
                            continue
                        log_entries.append({
                            'instance_id': instance_id,
                            'machine_name': machine_name,
                            'public_ip': public_ip,
                            'log_file_source': log_file_source,
                            'timestamp': parsed_log['timestamp'],
                            'message': parsed_log['message']
                        })
            except Exception as e:  # noqa: F841
                pass
        mmapped_file.close()
        print(f"Finished parsing log file '{local_file_name}' with {len(log_entries):,} log entries!")
    return log_entries

def parse_and_append_logs(local_file_name, instance_id, instance_name, public_ip, log_file_source):
    parsed_log_entries = parse_logs(local_file_name, instance_id, instance_name, public_ip, log_file_source)
    return parsed_log_entries

def remove_dupes_from_list_but_preserve_order_func(list_of_items):
    deduplicated_list = list(dict.fromkeys(list_of_items).keys())
    return deduplicated_list

def insert_log_entries(parsed_log_entries: List[Dict], session: Session, chunk_size: int = 250000, max_retries: int = 3):
    def commit_with_retry(session):
        for retry_count in range(max_retries):
            try:
                session.commit()
                break
            except OperationalError as e:
                if 'database is locked' in str(e).lower() and retry_count < max_retries - 1:
                    sleep_time = 2 ** retry_count
                    time.sleep(sleep_time)
                else:
                    raise
            except IntegrityError as e:
                session.rollback()
                print(f"IntegrityError occurred: {e}. Skipping this insert.")
    for idx in range(0, len(parsed_log_entries), chunk_size):
        chunk = parsed_log_entries[idx:idx + chunk_size]
        hash_ids = [calculate_hash_id(log_entry) for log_entry in chunk]
        hash_id_existence = redis_client.mget(hash_ids) 
        hash_id_exists_map = {hash_id: exists for hash_id, exists in zip(hash_ids, hash_id_existence)}
        new_log_entries = []
        for log_entry, log_entry_hash_id in zip(chunk, hash_ids):
            if not hash_id_exists_map.get(log_entry_hash_id): 
                redis_client.set(log_entry_hash_id, 1)
                new_log_entries.append(LogEntry(hash_id=log_entry_hash_id, **log_entry))
        new_log_entries = remove_dupes_from_list_but_preserve_order_func(new_log_entries)
        session.add_all(new_log_entries)
        commit_with_retry(session)
        
def get_status_info_for_instance(instance_id):
    global aws_region, aws_access_key_id, aws_secret_access_key, ssh_key_path, ansible_inventory_file
    print(f"Checking {instance_id}...")
    with open(ansible_inventory_file, 'r') as f:
        ansible_inventory = yaml.safe_load(f)
    public_ip, key_path = None, None
    instance_name = instance_id
    ssh_user = ansible_inventory['all']['vars']['ansible_user']
    hosts = ansible_inventory.get('all', {}).get('hosts', {})
    if instance_id in hosts:
        host_info = hosts[instance_id]
        public_ip = host_info.get('ansible_host')
        key_path = host_info.get('ansible_ssh_private_key_file')
    if not public_ip or not key_path:
        print(f"Instance {instance_id} is not in the Ansible inventory file, using AWS API to get public IP address and instance name.")
        ec2 = boto3.client('ec2', region_name=aws_region, aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)
        instance = ec2.describe_instances(InstanceIds=[instance_id])['Reservations'][0]['Instances'][0]
        public_ip = instance['PublicIpAddress']
        instance_name = get_instance_name(instance['Tags'])
    print(f"Now checking for SSH connectivity on instance named {instance_name} with instance ID of {instance_id} and public IP address of {public_ip}...")
    ssh_status, ssh_error = ssh_connect(public_ip, ssh_user, key_path if key_path else ssh_key_path)
    if ssh_status:
        print(f"{instance_id} ({instance_name}) is reachable by SSH")
        print(f"Now checking the status of the Pastel node on {instance_name} using `pastel-cli getinfo`...")
        output_dict = check_sn_status(public_ip, ssh_user, key_path if key_path else ssh_key_path, instance_name)
        print(f"Result of `getinfo` command on {instance_name}: {output_dict}")
        print(f"Now checking the masternode status of {instance_name} using `pastel-cli masternode list full` and `list extra`...")
        combined_masternode_status_dict = check_sn_masternode_status(public_ip, ssh_user, key_path if key_path else ssh_key_path, instance_name)
        print(f"Result of `masternode list full` and `list extra` command on {instance_name}: {combined_masternode_status_dict}")
        print(f"Now getting network data for {instance_name} using various network commands...")
        get_sn_network_data(public_ip, ssh_user, key_path if key_path else ssh_key_path, instance_name)
        print('Done getting network data!')
    else:
        if ssh_error == "Authentication failed.":
            print(f"{instance_id} ({instance_name}) has an authentication issue!")
        else:
            print(f"{instance_id} ({instance_name}) is not reachable by SSH!")

def insert_log_entries_worker(db_write_queue):
    Session = sessionmaker(bind=engine)
    none_count = 0
    while none_count < len(instance_ids):  # Continue processing until all instances have indicated they are done
        logs_to_insert = db_write_queue.get()
        if logs_to_insert is None:
            none_count += 1
        else:
            session = Session()
            try:
                session.bulk_insert_mappings(LogEntry, logs_to_insert)
                session.commit()
            except Exception as e:
                print(f"Error inserting log entries: {e}")
            finally:
                session.close()
        db_write_queue.task_done()

def process_instance(instance_id, db_write_queue):
    global aws_region, aws_access_key_id, aws_secret_access_key, ansible_inventory_file
    num_cores = os.cpu_count()
    if num_cores is not None:
        num_cores = max(1, num_cores - 2)
    with open(ansible_inventory_file, 'r') as f:
        ansible_inventory = yaml.safe_load(f)
    print(f"Checking {instance_id}...")
    public_ip, key_path = None, None
    instance_name = instance_id
    ssh_user = ansible_inventory['all']['vars']['ansible_user']
    hosts = ansible_inventory.get('all', {}).get('hosts', {})
    if instance_id in hosts:
        host_info = hosts[instance_id]
        public_ip = host_info.get('ansible_host')
        key_path = host_info.get('ansible_ssh_private_key_file')
    if not public_ip or not key_path:
        print('Instance is not in the Ansible inventory file, using AWS API to get public IP address and instance name.')
        ec2 = boto3.client('ec2', region_name=aws_region, aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)
        instance = ec2.describe_instances(InstanceIds=[instance_id])['Reservations'][0]['Instances'][0]
        public_ip = instance['PublicIpAddress']
        instance_name = get_instance_name(instance['Tags'])
    Session = sessionmaker(bind=engine)
    session = Session()
    user = ssh_user
    key_path = key_path if key_path else ssh_key_path
    print(f"Now checking for SSH connectivity on instance named {instance_name} with instance ID of {instance_id} and public IP address of {public_ip}...")
    ssh_status, ssh_error = ssh_connect(public_ip, user, key_path)
    if ssh_status:
        print(f"{instance_id} ({instance_name}) is reachable by SSH")
        log_files = [
            "/home/ubuntu/.pastel/debug.log",
            "/home/ubuntu/.pastel/supernode.log",
            "/home/ubuntu/.pastel/hermes.log",
            "/home/ubuntu/pastel_dupe_detection_service/logs/dd-service-log.txt",
            "/home/ubuntu/pastel_dupe_detection_service/logs/entry/entry.log"
        ]
        list_of_local_log_file_names = download_logs(public_ip, user, key_path, instance_name, log_files)
        print('Now parsing log files...')
        all_parsed_log_entries = []
        with ThreadPoolExecutor(max_workers=num_cores) as executor:
            futures = [executor.submit(parse_and_append_logs, local_file_name, instance_id, instance_name, public_ip, 
                        os.path.basename(local_file_name).split('.')[0].split('__')[-1].replace('debug', 'cnode').replace('entry', 'dd_entry')) 
                        for local_file_name in list_of_local_log_file_names]
        for future in futures:
            all_parsed_log_entries.extend(future.result())
        print(f'Done parsing log files on {instance_name}! Total number of log entries: {len(all_parsed_log_entries):,}')
        db_write_queue.put(all_parsed_log_entries)
        session.close()
        print(f'Done inserting log entries into database on {instance_name}! Number of log entries inserted: {len(all_parsed_log_entries):,}')
    else:
        if ssh_error == "Authentication failed.":
            print(f"{instance_id} ({instance_name}) has an authentication issue!")
        else:
            print(f"{instance_id} ({instance_name}) is not reachable by SSH!")
    db_write_queue.put(None)

def process_panic(panic, k_delta, session):
    time_start = panic.timestamp - k_delta
    time_end = panic.timestamp + k_delta
    related_logs = session.query(LogEntry).filter(
        LogEntry.instance_id == panic.instance_id,
        LogEntry.timestamp.between(time_start, time_end),
        LogEntry.log_file_source.in_(["systemd_log", "supernode", "hermes", "cnode", "dd-service-log", "dd_entry"])
    ).all()
    for log in related_logs:
        entry = EntriesBeforeAndAfterPanics(log_entry_id=log.id)
        session.add(entry)
    session.commit()

def analyze_panics(n_days=2, k_minutes=10):
    global engine
    print(f'Now analyzing panics over the previous {n_days} days and {k_minutes} minutes before and after the panic...')
    Session = sessionmaker(bind=engine)
    now = datetime.now()
    start_date = now - timedelta(days=n_days)
    k_delta = timedelta(minutes=k_minutes)
    session = Session()
    panics = session.query(LogEntry).filter(
        LogEntry.log_file_source == "systemd_log",
        LogEntry.timestamp.between(start_date, now),
        LogEntry.message.contains("panic")
    ).all()
    num_cores = os.cpu_count()
    if num_cores is not None:
        num_cores = max(1, num_cores - 2)
    with Pool(processes=num_cores) as pool:
        for panic in panics:
            session = Session()
            pool.apply_async(process_panic, (panic, k_delta, session))
            session.commit()
        pool.close()
        pool.join()
    create_view_sql = """
        CREATE VIEW entries_before_and_after_panics_view AS
        SELECT log_entries.* FROM log_entries
        JOIN entries_before_and_after_panics
        ON log_entries.id = entries_before_and_after_panics.log_entry_id
    """
    with engine.connect() as connection:
        try:
            connection.execute(sa.DDL(create_view_sql))
        except OperationalError as e:
            if "table entries_before_and_after_panics_view already exists" in str(e):
                pass
            else:
                raise e
    if len(panics) > 0:
        print(f'Done analyzing panics over the previous {n_days} days and {k_minutes} minutes before and after the panic! Found {len(panics):,} panics.')

def find_error_entries(n_days=3):
    global engine
    print('Now finding error entries...')
    Session = sessionmaker(bind=engine)
    session = Session()
    now = datetime.now()
    start_date = now - timedelta(days=n_days)
    error_keywords = ['error', 'invalid', 'failed', 'unable', 'panic']
    error_filters = or_(*(LogEntry.message.ilike(f"%{keyword}%") for keyword in error_keywords))
    error_entries = session.query(LogEntry).filter(
        error_filters,
        LogEntry.timestamp.between(start_date, now)
    ).all()
    Base.metadata.create_all(engine)
    error_entries_mappings = [{'log_entry_id': entry.id} for entry in error_entries]
    session.bulk_insert_mappings(MiscErrorEntries, error_entries_mappings)
    session.commit()
    create_view_sql = """
        CREATE VIEW misc_error_entries_view AS
        SELECT log_entries.* FROM log_entries
        JOIN misc_error_entries
        ON log_entries.id = misc_error_entries.log_entry_id
    """
    with engine.connect() as connection:
        try:
            connection.execute(sa.DDL(create_view_sql))
        except OperationalError as e:
            if "table misc_error_entries_view already exists" in str(e):
                pass
            else:
                raise e
    print(f'Done finding error entries! Found {len(error_entries):,} error entries and inserted them into the database.')
    
def get_latest_sn_statuses_func():
    global engine
    Session = sessionmaker(bind=engine)
    session = Session()
    try:
        # Check if the SNStatus table has any data
        sn_status_count = session.query(SNStatus).count()
        print(f"SNStatus table row count: {sn_status_count}")
        if sn_status_count == 0:
            print("SNStatus table is empty.")
            return pd.DataFrame()
        # Execute the subquery and main query
        subq = session.query(SNStatus.instance_name, sa.func.max(SNStatus.datetime_of_data).label('max_datetime')).group_by(SNStatus.instance_name).subquery()
        latest_statuses = session.query(SNStatus).join(subq, and_(SNStatus.instance_name == subq.c.instance_name, SNStatus.datetime_of_data == subq.c.max_datetime)).all()
        latest_sn_statuses_df = pd.DataFrame([status.to_dict() for status in latest_statuses])
        # Print the DataFrame to check the results
        print(f"Latest SN statuses DataFrame:\n{latest_sn_statuses_df}")
        return latest_sn_statuses_df
    except Exception as e:
        print(f"Error while fetching latest SNStatus: {str(e)}")
    finally:
        session.close()
        
def run_checks_on_latest_sn_statuses_data_func(latest_sn_statuses_df, instances=None):
    global engine
    Session = sessionmaker(bind=engine)
    session = Session()
    result = {}
    instances_with_status = set(latest_sn_statuses_df['instance_name'])
    if instances:
        instance_names = [get_instance_name(instance.tags) for instance in instances]
    else:
        instance_names = instances_with_status
    missing_status_responses = list(set(instance_names) - instances_with_status)
    if len(missing_status_responses) > 0:
        result['missing_status_responses'] = missing_status_responses
    else:
        result['missing_status_responses'] = "OK"
    block_heights = latest_sn_statuses_df['blocks'].values
    latest_block_height_reported_by_any_node = int(max(block_heights))
    block_heights_dict = latest_sn_statuses_df[['instance_name', 'blocks']].set_index('instance_name').to_dict()['blocks']
    out_of_sync_nodes = {
        instance_name: {
            "reported_block_height": int(reported_block_height),
            "number_of_blocks_out_of_sync": int(latest_block_height_reported_by_any_node) - int(reported_block_height)
        }
        for instance_name, reported_block_height in block_heights_dict.items()
        if reported_block_height != latest_block_height_reported_by_any_node
    }
    if len(out_of_sync_nodes) > 0:
        result['out_of_sync_nodes'] = {
            "latest_block_height_reported_by_any_node": int(latest_block_height_reported_by_any_node),
            "nodes": out_of_sync_nodes
        }
    else:
        result['out_of_sync_nodes'] = "OK"
    connections_dict = latest_sn_statuses_df[['instance_name', 'connections']].set_index('instance_name').to_dict()['connections']
    nodes_with_zero_connections = [instance_name for instance_name, connection in connections_dict.items() if connection == 0]
    if len(nodes_with_zero_connections) > 0:
        result['nodes_with_zero_connections'] = nodes_with_zero_connections
    else:
        result['nodes_with_zero_connections'] = "OK"
    health_check = NodeHealthChecks(
        missing_status_responses=result['missing_status_responses'],
        out_of_sync_nodes=result['out_of_sync_nodes'],
        nodes_with_zero_connections=result['nodes_with_zero_connections']
    )
    try:
        session.add(health_check)
        session.commit()
    except Exception as e:
        print(f"Error while inserting NodeHealthChecks: {str(e)}")
    finally:
        session.close()
    return result

def get_latest_sn_masternode_statuses_func():
    global engine
    Session = sessionmaker(bind=engine)
    session = Session()
    try:
        subq = session.query(
            SNMasternodeStatus.instance_name,
            sa.func.max(SNMasternodeStatus.datetime_of_data).label('max_datetime')
        ).group_by(SNMasternodeStatus.instance_name).subquery()
        latest_masternode_statuses = session.query(SNMasternodeStatus).filter(
            SNMasternodeStatus.instance_name == subq.c.instance_name,
            sa.func.julianday(subq.c.max_datetime) - sa.func.julianday(SNMasternodeStatus.datetime_of_data) <= 2 / (24*60*60)
        ).all()
        latest_masternode_statuses_df = pd.DataFrame([status.to_dict() for status in latest_masternode_statuses])
        return latest_masternode_statuses_df
    except Exception as e:
        print(f"Error while fetching latest SNMasternodeStatus: {str(e)}")
    finally:
        session.close()

def run_checks_on_latest_sn_masternode_statuses_data_func(latest_masternode_statuses_df, latest_sn_statuses_df):
    global engine
    Session = sessionmaker(bind=engine)
    session = Session()     
    results = {}
    masternode_collateral_txid_and_outpoint_to_instance_name_dict = dict(zip(latest_sn_statuses_df['masternode_collateral_txid_and_outpoint'], latest_sn_statuses_df['instance_name']))
    outlier_reports = {"reporting_SNs": {}}
    grouped = latest_masternode_statuses_df[latest_masternode_statuses_df.masternode_rank != -1].groupby(['instance_name', 'masternode_collateral_txid_and_outpoint'])['masternode_rank'].apply(list)
    ranks = grouped.values
    majority_ranks = [Counter(rank).most_common(1)[0][0] for rank in zip(*ranks)]
    for (reporting_sn, reported_sn), reported_ranks in grouped.items():
        for reported_rank, majority in zip(reported_ranks, majority_ranks):
            if reported_rank != majority:
                if reporting_sn not in outlier_reports["reporting_SNs"]:
                    outlier_reports["reporting_SNs"][reporting_sn] = {"disagreements_with_majority_rank": {}}
                if majority not in outlier_reports["reporting_SNs"][reporting_sn]["disagreements_with_majority_rank"]:
                    outlier_reports["reporting_SNs"][reporting_sn]["disagreements_with_majority_rank"][majority] = {"reported_ranks_instead": []}
                outlier_reports["reporting_SNs"][reporting_sn]["disagreements_with_majority_rank"][majority]["reported_ranks_instead"].append((reported_rank, reported_sn))
    explanations = []
    for reporting_sn, sn_data in outlier_reports["reporting_SNs"].items():
        for majority_rank, rank_data in sn_data["disagreements_with_majority_rank"].items():
            for reported_rank, reported_sn in rank_data["reported_ranks_instead"]:
                try:
                    reported_sn_instance_name = masternode_collateral_txid_and_outpoint_to_instance_name_dict[reported_sn]
                    reported_sn_instance_name = reported_sn_instance_name.split(" - ")[-1]
                    reporting_sn_instance_name = reporting_sn.split(" - ")[-1]
                    explanation = f"Reporting SN {reporting_sn_instance_name} disagreed with the majority rank {majority_rank} and reported the rank {reported_rank} instead for SN {reported_sn_instance_name}."
                    explanations.append(explanation)
                except KeyError:
                    pass
    results['outlier_reports_explanations'] = explanations                
    all_new_start_required = latest_masternode_statuses_df.groupby('instance_name')['masternode_status_message'].all() == "NEW_START_REQUIRED"
    if not any(all_new_start_required.values.tolist()):
        results['all_new_start_required'] = 'OK'
    else:
        results['all_new_start_required'] = all_new_start_required.to_dict()
    new_start_required_sns = latest_masternode_statuses_df[latest_masternode_statuses_df.masternode_status_message == "NEW_START_REQUIRED"]["masternode_collateral_txid_and_outpoint"].unique()
    sn_new_start_required_dict = {}
    for sn in new_start_required_sns:
        reporting_df = latest_masternode_statuses_df[(latest_masternode_statuses_df.masternode_collateral_txid_and_outpoint  == sn) & (latest_masternode_statuses_df.masternode_status_message == "NEW_START_REQUIRED")]
        reporting_sns = reporting_df['instance_name'].unique().tolist()
        reporting_sns.sort()
        if len(reporting_sns) > 1:
            try:
                sn_instance_name = masternode_collateral_txid_and_outpoint_to_instance_name_dict[sn]
                sn_new_start_required_dict[sn_instance_name] = {"instance_name_of_reporting_sn": reporting_sns}
            except Exception as e:  # noqa: F841
                pass
    results['supernodes_reported_to_be_in_new_start_required_mode'] = sn_new_start_required_dict
    masternode_health_check = NodeMasternodeHealthChecks(
        masternode_rank_outlier_report_explanations=results['outlier_reports_explanations'],
        all_new_start_required=results['all_new_start_required'],
        supernodes_reported_to_be_in_new_start_required_mode=results['supernodes_reported_to_be_in_new_start_required_mode']
    )  
    try:
        session.add(masternode_health_check)
        session.commit()        
        session.close()
    except Exception as e:
        print(f"Error while inserting NodeMasternodeHealthChecks: {str(e)}")
    finally:
        session.close()          
    return results

def create_view_of_connection_counts():
    global engine
    create_view_sql = """
    CREATE VIEW connection_count_per_service_view AS
    SELECT public_ip, instance_name, lsof__command, datetime_of_data_truncated, COUNT(*) as count
    FROM (
        SELECT sn.*, SUBSTR(sn.datetime_of_data, 1, 15) as datetime_of_data_truncated
        FROM sn_network_activity_lsof sn
        WHERE sn.lsof__type = 'IPv4' OR sn.lsof__type = 'IPv6'
    )
    WHERE SUBSTR(datetime_of_data_truncated, 1, 15) >= (
        SELECT SUBSTR(MAX(datetime_of_data), 1, 15)
        FROM sn_network_activity_lsof
    )
    GROUP BY public_ip, instance_name, lsof__command, datetime_of_data_truncated;
    """
    with engine.connect() as connection:
        try:
            connection.execute(sa.DDL(create_view_sql))
        except OperationalError as e:
            if "table connection_count_per_service_view already exists" in str(e):
                pass
            else:
                raise e
    print('View created!')

def stop_existing_datasette():
    ps_output = subprocess.check_output(['ps', 'aux']).decode('utf-8')
    datasette_processes = [line for line in ps_output.split('\n') if 'datasette' in line and not 'grep' in line]  # noqa: E713
    for process in datasette_processes:
        pid = int(process.split()[1])
        os.kill(pid, signal.SIGTERM)
        print(f"Stopped existing Datasette process with PID {pid}")

def restart_datasette(datasette_path: str, sqlite_path: str, host: str, port: int, time_limit_ms: int):
    stop_existing_datasette()
    cmd = f"{datasette_path} {sqlite_path} -h {host} -p {port} --setting sql_time_limit_ms {time_limit_ms}"
    with open(os.devnull, 'w') as dev_null:
        subprocess.Popen(shlex.split(cmd), stdout=dev_null, stderr=dev_null)
    print(f"Datasette started with the new SQLite file at http://{host}:{port}")

def backup_table(table_name):
    with sqlite3.connect(sqlite_file_path) as conn:
        df = pd.read_sql(f'SELECT * FROM {table_name}', conn)
        backup_file_name = f'{backup_base_path}_{table_name}.csv'
        df.to_csv(backup_file_name, index=False)        
        timestamp = datetime.now().strftime('__%Y_%m_%d__%H_%M_%S')
        backup_dir = BASE_PATH + config("BACKUP_DATABASE_TABLE_CSV_FILES_DIR_NAME", cast=str)
        os.makedirs(backup_dir, exist_ok=True)
        backup_file_name_timestamped = f'{table_name}{timestamp}.csv'
        backup_file_path_timestamped = os.path.join(backup_dir, backup_file_name_timestamped)
        shutil.copy2(backup_file_name, backup_file_path_timestamped)                
        print(f"Backed up {table_name} to {backup_file_name} and {backup_file_path_timestamped}")

def load_table(table_name):
    global earliest_date_cutoff
    backup_path = f'{backup_base_path}_{table_name}.csv'
    if os.path.exists(backup_path):
        df = pd.read_csv(backup_path)
        initial_len = len(df)
        print(f"Loaded {table_name} from {backup_path}")
        df = df[pd.to_datetime(df['datetime_of_data']) > earliest_date_cutoff]
        print(f"Filtered {table_name} to only include entries after {earliest_date_cutoff} ({len(df)} entries retained, {initial_len - len(df)} entries removed for being too old)")
        with sqlite3.connect(sqlite_file_path) as conn:
            df.to_sql(table_name, conn, if_exists='append', index=False)

def get_status_data_in_parallel_func(instance_ids):
    if use_sequential_data_collection:
        print('\n\nNOTE: USING SEQUENTIAL DATA COLLECTION\n\n')
        for instance_id in instance_ids:
            get_status_info_for_instance(instance_id)
    else:
        with concurrent.futures.ThreadPoolExecutor() as executor:
            executor.map(get_status_info_for_instance, instance_ids)        

def get_instance_ids_from_inventory(inventory_file):
    with open(inventory_file, 'r') as file:
        inventory = yaml.safe_load(file)
    instance_ids = []
    hosts = inventory.get('all', {}).get('hosts', {})
    instance_ids.extend(hosts.keys())
    return instance_ids

def main():
    num_cores = os.cpu_count()
    if num_cores is not None:
        num_cores = max(1, num_cores - 2)
    manager = Manager()
    db_write_queue = manager.JoinableQueue()
    db_writer_thread = threading.Thread(target=insert_log_entries_worker, args=(db_write_queue,))  
    db_writer_thread.start()
    with ProcessPoolExecutor(max_workers=num_cores) as executor:
        futures = []
        for instance_id in instance_ids:
            future = executor.submit(process_instance, instance_id, db_write_queue)
            futures.append(future)
        for future in futures:
            try:
                future.result()
            except Exception as e:
                print(f"Error processing instance: {e}")
    db_write_queue.put(None)
    db_writer_thread.join()

redis_client = redis.StrictRedis(host='localhost', port=6379, db=0)

if __name__ == "__main__":
    profile_code = 0
    profile_output_file = "profiling_data.prof"
    os.system('clear')
    print('Clearing existing Redis contents...')
    redis_client.flushall()
    print('Done clearing Redis contents!')
    aws_access_key_id = config("AWS_ACCESS_KEY_ID", cast=str)
    aws_secret_access_key = config("AWS_SECRET_ACCESS_KEY", cast=str)
    aws_region = config("AWS_REGION", cast=str)
    ansible_inventory_file = config("ANSIBLE_INVENTORY_FILE", cast=str)
    earliest_date_cutoff = datetime.now() - timedelta(days=7)
    print('Clearing existing log files and database...')
    downloaded_log_files_path = config("DOWNLOADED_LOG_FILES_PATH", cast=str)
    existing_log_files = glob.glob(downloaded_log_files_path + '/*')
    sqlite_file_path = config("SQLITE_FILE_PATH", cast=str)
    node_status_data_backup_path = config("NODE_STATUS_DATA_BACKUP_PATH", cast=str)
    backup_base_path = BASE_PATH + node_status_data_backup_path
    for file in existing_log_files:
        os.remove(file)
    try:
        os.remove(sqlite_file_path)
    except FileNotFoundError:
        pass
    log_directory = BASE_PATH
    log_files_pattern = os.path.join(log_directory, "*.log")
    log_files = glob.glob(log_files_pattern)
    if len(log_files) > 5:
        sorted_log_files = sorted(log_files, key=os.path.getctime, reverse=True)
        for log_file in sorted_log_files[5:]:
            os.remove(log_file)
    print('Done clearing existing log files and database!')
    print('\n\nNow starting log analysis...')
    engine = sa.create_engine(f'sqlite:///{sqlite_file_path}', connect_args={'timeout': 20}, pool_size=10, max_overflow=20)
    Base.metadata.create_all(engine)
    print('Now attempting to load historical node status data from backup...')
    try:
        load_table('sn_masternode_status')
        load_table('sn_status')
        load_table('sn_network_activity_netstat')
        load_table('sn_network_activity_lsof')
        load_table('sn_network_activity_ss')
        print('Done loading historical node status data from backup!')
    except Exception as e:
        print(f"Error loading historical node status data from backup: {e}")
    backup_database_table_csv_files_dir_name = config("BACKUP_DATABASE_TABLE_CSV_FILES_DIR_NAME", cast=str)
    backup_csv_files = glob.glob(backup_database_table_csv_files_dir_name + '/*.csv')
    number_of_backup_csv_files_to_keep = config("NUMBER_OF_BACKUP_CSV_FILES_TO_KEEP", cast=int)
    if len(backup_csv_files) > number_of_backup_csv_files_to_keep:
        sorted_backup_csv_files = sorted(backup_csv_files, key=os.path.getctime, reverse=True)
        for backup_csv_file in sorted_backup_csv_files[number_of_backup_csv_files_to_keep:]:
            os.remove(backup_csv_file)
            print(f"Deleted backup CSV file {backup_csv_file} because it was too old (more than {number_of_backup_csv_files_to_keep} files in the backup directory)")                    
    instance_name_prefix = config("INSTANCE_NAME_PREFIX", cast=str)
    non_aws_instance_ids = get_instance_ids_from_inventory(ansible_inventory_file)
    try:
        instances = get_instances_with_name_prefix(instance_name_prefix, aws_access_key_id, aws_secret_access_key, aws_region)
        aws_instance_ids = [instance.id for instance in instances]        
    except Exception as e:
        print("Error getting instances from AWS API: ", e)
        aws_instance_ids = []
        instances = None
    instance_ids = aws_instance_ids + non_aws_instance_ids
    print(f'Now collecting status info for {len(instance_ids)} instances...')
    use_sequential_data_collection = 1
    get_status_data_in_parallel_func(instance_ids)
    print('Done collecting status info for all instances!')
    latest_sn_statuses_df = get_latest_sn_statuses_func()
    latest_masternode_statuses_df = get_latest_sn_masternode_statuses_func()
    sn_status_check_results_dict = run_checks_on_latest_sn_statuses_data_func(latest_sn_statuses_df, instances)
    sn_status_check_results_json = json.dumps(sn_status_check_results_dict, indent=4)
    print(f'\n\nResults of checks on latest SN status data:\n{sn_status_check_results_json}')
    sn_masternode_status_check_results_dict = run_checks_on_latest_sn_masternode_statuses_data_func(latest_masternode_statuses_df, latest_sn_statuses_df)
    sn_masternode_status_check_results_json = json.dumps(sn_masternode_status_check_results_dict, indent=4)
    print(f'\n\nResults of checks on latest SN masternode status data:\n{sn_masternode_status_check_results_json}')
    if not profile_code:
        main()
    else:
        cProfile.run("main()", profile_output_file)
    print('\n\nDone ingesting log files!')
    analyze_panics(n_days=1, k_minutes=10)
    find_error_entries()
    create_view_of_connection_counts()
    print('\n\nNow backing up database tables for `sn_masternode_status` and `sn_status` ...')
    backup_table('sn_masternode_status')
    backup_table('sn_status')
    backup_table('sn_network_activity_netstat')
    backup_table('sn_network_activity_lsof')
    backup_table('sn_network_activity_ss')
    print('Done backing up database tables!')
    print('All Completed!')
    datasette_path =  config("DATASETTE_PATH", cast=str)
    sqlite_path = BASE_PATH + sqlite_file_path
    host = config("HOST", cast=str)
    port = config("PORT", cast=int)
    time_limit_ms = config("TIME_LIMIT_MS", cast=int)
    restart_datasette(datasette_path, sqlite_path, host, port, time_limit_ms)
    try:
        os.remove(lock_file)
    except Exception as e: # noqa: F841
        pass
    if profile_code:
        with open("profiling_report.txt", "w") as f:
            stats = pstats.Stats(profile_output_file, stream=f)
            stats.sort_stats("cumulative")
            stats.print_stats()
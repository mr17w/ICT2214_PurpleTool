#!/usr/bin/env python3
import argparse
import sys
import os
from crontab import CronTab

def schedule_script(script_path, time_str):
    # Validate and parse the time string (expected format: HH:MM)
    try:
        hour, minute = map(int, time_str.split(':'))
        if not (0 <= hour <= 23 and 0 <= minute <= 59):
            raise ValueError
    except ValueError:
        print("Error: Time must be provided in HH:MM format with valid hour (0-23) and minute (0-59), e.g., 14:30.")
        sys.exit(1)
    
    # If script_path is not absolute, resolve it relative to this scheduler's directory.
    if not os.path.isabs(script_path):
        scheduler_dir = os.path.dirname(os.path.abspath(__file__))
        script_path = os.path.join(scheduler_dir, script_path)
    
    # Resolve the absolute path and directory of the target script
    script_abs = os.path.abspath(script_path)
    script_dir = os.path.dirname(script_abs)
    
    # Use the current user's crontab
    cron = CronTab(user=True)
    
    # Remove any existing jobs scheduled by this script (identified by the comment)
    cron.remove_all(comment='Scheduled by scheduleCVE script')
    
    # Build the command:
    # Change to the script's directory and then execute the script with the current Python interpreter.
    # Paths are quoted to handle spaces and special characters.
    command = f'cd "{script_dir}" && "{sys.executable}" "{script_abs}"'
    
    # Create a new cron job with a comment for easy identification
    job = cron.new(command=command, comment='Scheduled by scheduleCVE script')
    
    # Set the job to run daily at the specified time (minute, hour, day of month, month, day of week)
    job.setall(minute, hour, '*', '*', '*')
    
    # Write the updated cron jobs to the crontab
    cron.write()
    print(f"Scheduled {script_abs} to run daily at {time_str} in its directory {script_dir}")

def get_arguments():
    parser = argparse.ArgumentParser(
        description='Schedule a Python script to run daily at a given time using cron.'
    )
    parser.add_argument('script_path', help='Path to the Python script to schedule.')
    parser.add_argument('time', help='Time in HH:MM format (e.g., 14:30).')
    args = parser.parse_args()
    return args.script_path, args.time

if __name__ == '__main__':
    script_path, time_str = get_arguments()
    schedule_script(script_path, time_str)

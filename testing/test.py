import subprocess

# Start a shell process
process = subprocess.Popen(['ls', '-l'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

# Get the output and errors
stdout, stderr = process.communicate()

# Print the output
print(stdout)

# Print any errors
if stderr:
    print(f"Errors: {stderr}")

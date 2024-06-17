import subprocess

def shell():
    while True:
        try:
            # Read command from user
            command = input(">>> ").strip()

            # Exit the shell
            if command.lower() in ('exit', 'quit'):
                break

            if command:
                # Start a subprocess and redirect output
                process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

                # Continuously read output and error
                while True:
                    output = process.stdout.readline()
                    if output == '' and process.poll() is not None:
                        break
                    if output:
                        print(output.strip())
                        if output.strip() == '':
                            print("[Empty Line Detected]")
                
                err = process.stderr.read()
                if err:
                    print(err.strip())

        except KeyboardInterrupt:
            print("\nType 'exit' or 'quit' to leave the shell.")
        except Exception as e:
            print(f"An error occurred: {e}")

if __name__ == "__main__":
    shell()

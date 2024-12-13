## IPv6 Ethernet Harness

Contains experimental code for testing and extending network functionality. This is certainly not production code.

---

### Prepare the Environment

```
# Install the virtual environment
python3 -m venv .venv

# Enter the virtual environment
. .venv/bin/activate

# Install python3 requirements
python3 -m pip3 install -r requirements.txt

# Exit the virtual environment
deactivate
```

### Build Instructions

Assuming LLVM build files are in /cheriot-tools/bin.

```
# Enter the virtual environment
. .venv/bin/activate

# Configure cheriot-tools path
xmake config --sdk=/cheriot-tools

# Build the project
xmake

# Create firmware.uf2
xmake run

# Exit the virtual environment
deactivate
```
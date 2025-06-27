# packet-handler-test-task

A C++ application for analyzing network packet files in "locomotive" format (2-byte packet length prefix).

# Build & Run

```bash
# Clone repository
git clone git@github.com:romak00/packet-handler-test-task.git
cd packet-handler-test-task

# Build
mkdir build && cd build
cmake .. && make

# Run
./bin/packethandler <file_name>
```

# Run Tests

```bash
cd build
./bin/tests
```
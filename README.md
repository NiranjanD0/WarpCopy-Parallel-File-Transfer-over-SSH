# WarpCopy - Parallel File Transfer over SSH

A multithreaded file transfer tool written in C that uses `libssh` to download files from a server in parallel chunks. It is designed as a high-performance alternative to `scp` for downloading large files.

---

## Features

* **Parallel Downloads:** Spawns multiple threads on the client to download different segments of a file simultaneously.
* **Secure:** All data transfer is encrypted over the SSH protocol, leveraging the `libssh` library.
* **Integrity Check:** The client verifies the downloaded file's SHA-256 hash against the server's original hash to ensure the transfer was not corrupted.
* **On-Demand Metadata:** The client first queries the server for the file's size and hash before initiating the download.

---

## Prerequisites

Before you begin, make sure you have the necessary build tools and development libraries installed.

* A C compiler (e.g., `gcc`)
* `make`
* `libssh` (development libraries)
* `openssl` (development libraries)

You can install these on **Debian/Ubuntu-based** systems with:

```bash
sudo apt update
sudo apt install build-essential libssh-dev libssl-dev
```

On Arch-based systems:
```bash
sudo pacman -S base-devel libssh openssl
```

---

## Compiling

Simply run `make` or `make build` from the project's root directory. This will compile both the `server` and `client` executables.

```bash
make build
```

---

## How to Run

You need two machines: a **server** (which hosts the file) and a **client** (which will download the file).

### 1. On the Server Machine

The server needs access to your system's SSH host key (usually located at `/etc/ssh/ssh_host_rsa_key`). Because this file is protected, you must run the server with `sudo`.

1.  **Place the file** you want to serve (e.g., `my_big_file.zip`) in the same directory as the `server` executable.
2.  **Run the server:**
    ```bash
    sudo ./server
    ```
3.  **Configure your firewall.** Make sure the server's firewall allows incoming TCP traffic on port `8080`.
    * If you are using `ufw` (Uncomplicated Firewall), you can add a rule with the following commands:
        ```bash
        sudo ufw allow 8080/tcp
        sudo ufw reload
        ```
    * If your server is hosted on a cloud provider (like AWS, Azure, or GCP), you must **also** configure the Network Security Group or VPC Firewall Rules in your provider's web console to allow inbound traffic on TCP port `8080`.

### 2. On the Client Machine

The client does not require `sudo` privileges.

1.  **Run the client:**
    ```bash
    # Usage: 

    # ./client

    # Or

    #./client <server_ip_or_domain <absolute_path_on_server> <num_threads>

    # Example: ./client vm.niranjan0.xyz /home/nir/test.zip 4
    ```
2.  This command will download the file using 4 parallel connections and saves it to a local `Downloads/` folder with the original filename.

---

## How It Works

The program follows a specific protocol to ensure an efficient and verifiable transfer.

1.  **The `INFO` Request:** The client first opens a single SSH connection to the server and sends an `INFO <file_name>` command.
2.  **The Server's Reply:** The server receives the request, calculates the target file's SHA-256 hash and total size, and sends this metadata back to the client as a single string (e.g., `"50000000 9c623...410db"`).
3.  **The Client's Plan:** The client receives the metadata. It now has the expected hash for verification and the total size for calculating segments.
4.  **Parallel Connections:** The client spawns the user-specified number of threads (e.g., 4 threads), each opening its own SSH session.
5.  **The `GET` Request:** Each thread requests a unique segment of the file via a `GET` command.
    * Thread 0 asks for: `GET <file_name> 0 4`
    * Thread 1 asks for: `GET <file_name> 1 4`
    * ...and so on.
6.  **Segment Delivery:** The server handles each connection concurrently, streaming the appropriate segment of the file to each client thread.
7.  **File Reassembly:** On the client, threads write directly into their file chunk offset using `pwrite()`, allowing simultaneous writes without overlap or mutexes.
8.  **Retries:** Failed transfers retry up to 3 times per thread, resetting write offsets correctly.
9.  **Verification:** Once all threads have completed, the client calculates the SHA-256 hash of the newly created local file and compares it to the hash received from the server in step 2. If they match, the transfer is considered successful.

## Note

Since each download thread opens its own SSH session. Some servers limit concurrent sessions, causing refusals if too many threads run.

To fix:
```bash
sudo vi /etc/ssh/sshd_config
```
Add or update:
```
MaxStartups 50:30:100
MaxSessions 50
```
Then restart SSH:
```bash
sudo systemctl restart sshd
```
tweak values as needed to match ur setup.

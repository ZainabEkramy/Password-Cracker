# Parallel Password Cracker

Multi-threaded password cracking tool with dictionary attack and GUI.

## Features

- Dictionary attack using wordlist
- Parallel processing for speed
- GUI with Tkinter
- C backend + Python interface

## Tech Stack

- C (core logic)
- Python + Tkinter (GUI)
- Multi-threading

## How to Run

### 1. Compile the C program

```bash
gcc PasswordCracker.c -o a.exe
```

### 2. Add a wordlist

- Download any wordlist (e.g., rockyou.txt)
- Rename it to `dictionary.txt`
- Place it in the same folder

### 3. Run the GUI

```bash
python passwordGUI.py
```

### 4. Use it

- Enter target password
- Click "Start Cracking"

## Disclaimer

> For educational purposes only. Use only on systems you own or have permission to test.

Real Antivirus in Python
Project Overview

This project implements a simple antivirus program in Python. The program scans a user-specified folder for files that match known virus signatures and quarantines any detected threats. It is designed for educational purposes and demonstrates basic file scanning, signature matching, and quarantine operations.

Features

Loads known virus signatures from a file (signatures.txt).

Scans a folder recursively for infected files.

Detects and lists files matching virus signatures.

Moves infected files to a quarantine folder to prevent accidental damage.

Simple command-line interface for easy interaction.

Project Components

Signature Loader: Loads virus signatures from signatures.txt.

Scanner: Recursively scans folders and compares files against the loaded signatures.

Quarantine Module: Moves flagged infected files to a quarantine folder.

User Interface: Command-line interface for folder input and output display.

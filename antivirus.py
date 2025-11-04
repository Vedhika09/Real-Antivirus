import os

# --- Create Test Folder and Virus Files ---
desktop = os.path.join(os.path.expanduser("~"), "Desktop")
test_folder = os.path.join(desktop, "TestFolder")

# Create TestFolder if it doesn't exist
os.makedirs(test_folder, exist_ok=True)

# Create dummy files
virus_files = ["malware123.exe", "testvirus.exe"]
normal_files = ["normal.txt", "readme.docx"]

for f in virus_files + normal_files:
    path = os.path.join(test_folder, f)
    if not os.path.exists(path):
        with open(path, "w") as file:
            file.write("This is a test file.")

# --- Virus Signatures ---
signatures = [v.lower() for v in virus_files]

# --- Scan Folder ---
def scan_folder(folder_path, signatures):
    infected = []
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            file_lower = file.lower()
            print(f"Checking file: {file}")  # debug
            if file_lower in signatures:
                infected.append(os.path.join(root, file))
    return infected

# --- Quarantine (optional) ---
def quarantine_files(files):
    print("\nQuarantining infected files...")
    for f in files:
        print(f"Quarantined: {f}")

# --- Main ---
def main():
    print("=== Python Real Antivirus ===\n")
    print(f"Scanning folder: {test_folder}\n")
    infected_files = scan_folder(test_folder, signatures)
    if infected_files:
        print(f"\nScan complete! {len(infected_files)} virus(es) found:\n")
        for f in infected_files:
            print(f)
        quarantine_files(infected_files)
    else:
        print("\nNo viruses found.\nScan complete.")
    print("\n=== Scan Finished ===")

if __name__ == "__main__":
    main()

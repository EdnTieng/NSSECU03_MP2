import os
import subprocess
import pandas as pd
import glob

# Define output directory
output_dir = r"C:\ToolOutputs"
os.makedirs(output_dir, exist_ok=True)  # Ensure output directory exists

# Paths to forensic tools (Update paths accordingly)
mftecmd_path = r"C:\Users\eiden\OneDrive\Desktop\school shit\NSSECU3\MFTECmd.exe"
amcache_parser_path = r"C:\Users\eiden\OneDrive\Desktop\school shit\NSSECU3\AmcacheParser.exe"
lecmd_path = r"C:\Users\eiden\OneDrive\Desktop\school shit\NSSECU3\LECmd.exe"


def run_command(command):
    """Run a command and capture output."""
    try:
        result = subprocess.run(command, capture_output=True, text=True, shell=True)
        print(result.stdout)
        if result.stderr:
            print("Error:", result.stderr)
    except Exception as e:
        print("❌ Failed to execute command:", str(e))


def run_mftecmd():
    print("🔍 Running MFTECmd...")
    command = [mftecmd_path, "-f", "C:\\$MFT", "--csv", output_dir, "--at"]
    run_command(command)


def run_amcache_parser():
    print("🔍 Running AmcacheParser...")
    command = [amcache_parser_path, "-f", "C:\\Windows\\AppCompat\\Programs\\Amcache.hve", "--csv", output_dir,
               "--csvf", "amcache_output.csv"]
    run_command(command)


def run_lecmd_analysis():
    print("🔍 Running LECmd...")
    lnk_dir = os.path.expandvars(r"C:\\Users")
    command = [lecmd_path, "-d", lnk_dir, "--csv", output_dir]
    run_command(command)
    print(f"✅ LECmd analysis completed. Output saved in: {output_dir}")


def get_latest_file(pattern):
    """Find the latest CSV file matching a pattern in the output directory."""
    files = glob.glob(os.path.join(output_dir, pattern))
    return max(files, key=os.path.getmtime) if files else None


def load_csv(file_path):
    """Load CSV file."""
    return pd.read_csv(file_path, low_memory=False)


# Function to convert hex to decimal
def hex_to_dec(value):
    if isinstance(value, str) and value.startswith("0x"):
        return int(value, 16)  # Convert hex to decimal
    return pd.to_numeric(value, errors='coerce')  # Keep numeric values as is


def rename_columns(df, prefix):
    """Renames columns by adding a prefix to indicate the tool they came from."""
    return df.rename(columns={col: f"[{prefix}] {col}" for col in df.columns})


def process_data():
    print("📂 Detecting latest forensic reports...")

    # Automatically detect the latest CSV files
    mftecmd_file = get_latest_file("*MFTECmd*Output.csv")
    lecmd_file = get_latest_file("*LECmd_Output.csv")
    amcache_unassociated_file = get_latest_file("*amcache_output_UnassociatedFileEntries.csv")

    if not (mftecmd_file and lecmd_file and amcache_unassociated_file):
        print("❌ Error: One or more required CSV files are missing.")
        return

    print(f"Using:\n - MFTECmd: {mftecmd_file}\n - LECmd: {lecmd_file}\n - Amcache: {amcache_unassociated_file}")

    print("📊 Loading and processing data...")

     # Load and rename columns
    mfte_data = rename_columns(load_csv(mftecmd_file), "MFTECmd")
    lecmd_data = rename_columns(load_csv(lecmd_file), "LECmd")
    amcache_data = rename_columns(load_csv(amcache_unassociated_file), "Amcache")

    # Apply conversion to LECmd columns
    lecmd_data['[LECmd] TargetMFTEntryNumber'] = lecmd_data['[LECmd] TargetMFTEntryNumber'].apply(hex_to_dec)
    lecmd_data['[LECmd] TargetMFTSequenceNumber'] = lecmd_data['[LECmd] TargetMFTSequenceNumber'].apply(hex_to_dec)

    # Convert necessary columns to numeric for merging
    mfte_data['[MFTECmd] EntryNumber'] = pd.to_numeric(mfte_data['[MFTECmd] EntryNumber'], errors='coerce')
    mfte_data['[MFTECmd] SequenceNumber'] = pd.to_numeric(mfte_data['[MFTECmd] SequenceNumber'], errors='coerce')
    lecmd_data['[LECmd] TargetMFTEntryNumber'] = pd.to_numeric(lecmd_data['[LECmd] TargetMFTEntryNumber'], errors='coerce')
    lecmd_data['[LECmd] TargetMFTSequenceNumber'] = pd.to_numeric(lecmd_data['[LECmd] TargetMFTSequenceNumber'], errors='coerce')

    # Merge MFTECmd with LECmd using MFT Entry Number
    merged_data = pd.merge(
        mfte_data, 
        lecmd_data, 
        left_on=['[MFTECmd] EntryNumber', '[MFTECmd] SequenceNumber'],
        right_on=['[LECmd] TargetMFTEntryNumber', '[LECmd] TargetMFTSequenceNumber'],
        how='outer',
        suffixes=('_MFT', '_LNK')
    )

    # Merge with Amcache data using FullPath
    merged_data = pd.merge(
        merged_data, 
        amcache_data, 
        left_on='[MFTECmd] FileName', 
        right_on='[Amcache] Name', 
        how='outer'
    )

    # Keep only rows where the file appears in either Amcache (executed) or LNK (accessed)
    merged_data = merged_data[(pd.notna(merged_data['[Amcache] Name'])) | (pd.notna(merged_data['[LECmd] TargetMFTEntryNumber']))]

    # Add forensic analysis column
    def analyze_file(row):
        in_mft = pd.notna(row['[MFTECmd] EntryNumber'])
        in_amcache = pd.notna(row['[Amcache] Name'])
        in_lnk = pd.notna(row['[LECmd] TargetMFTEntryNumber'])

        if in_mft and in_amcache and in_lnk:
            return "Executed & Accessed & Exists in MFT"  # 🔥 New condition
        elif in_mft and in_amcache:
            return "Executed & Exists in MFT"
        elif in_amcache and not in_mft:
            return "Executed but Deleted"
        elif in_lnk and not in_mft:
            return "Accessed & Possibly Deleted"
        elif in_lnk and not in_amcache:
            return "Accessed (LNK) but Not Executed"
        else:
            return "Unknown"

    merged_data['Forensic Analysis'] = merged_data.apply(analyze_file, axis=1)

    # Save the correlated forensic report
    correlated_output = os.path.join(output_dir, "Correlated_Forensic_Report.csv")
    merged_data.to_csv(correlated_output, index=False)

    print(f"✅ Correlated forensic report saved at: {correlated_output}")

def cleanup_files():
    """Delete all files in output_dir except Correlated_Forensic_Report.csv."""
    for file in os.listdir(output_dir):
        file_path = os.path.join(output_dir, file)
        if os.path.isfile(file_path) and file != "Correlated_Forensic_Report.csv":
            try:
                os.remove(file_path)
                print(f"🗑️ Deleted: {file}")
            except Exception as e:
                print(f"❌ Error deleting {file}: {e}") 

if __name__ == "__main__":
    run_mftecmd()
    run_amcache_parser()
    run_lecmd_analysis()
    process_data()
    cleanup_files()
    print("🎯 Forensic analysis completed! Check:", output_dir)

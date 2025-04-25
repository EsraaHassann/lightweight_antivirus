import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox
from engine import scan_directory, scan_for_heuristics, check_file_signature, check_file_heuristics, quarantine_file

class AntivirusApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Lightweight Antivirus Solution")
        self.root.geometry("400x250")

        # Add a label
        self.label = tk.Label(root, text="Select a file or folder to scan for malware", font=("Arial", 14))
        self.label.pack(pady=20)

        # Add a button to select folder
        self.folder_button = tk.Button(root, text="Scan Folder", command=self.scan_folder)
        self.folder_button.pack(pady=10)

        # Add a button to select file
        self.file_button = tk.Button(root, text="Scan File", command=self.scan_file)
        self.file_button.pack(pady=10)

    def scan_folder(self):
        folder_selected = filedialog.askdirectory()
        if folder_selected:
            messagebox.showinfo("Scanning", "Scanning the selected folder for malware...")
            # Start scanning folder
            scan_directory(folder_selected)
            scan_for_heuristics(folder_selected)
            messagebox.showinfo("Scan Complete", "The scan is complete.")
        else:
            messagebox.showwarning("No Folder", "Please select a folder to scan.")

    def scan_file(self):
        file_selected = filedialog.askopenfilename(filetypes=[("All Files", "*.*")])
        if file_selected:
            messagebox.showinfo("Scanning", f"Scanning the file: {file_selected} for malware...")
            # Check if the file is infected using both signature and heuristic methods
            if check_file_signature(file_selected):
                quarantine_file(file_selected)
                messagebox.showinfo("Malware Detected", f"Malware detected in {file_selected}. It has been quarantined.")
            elif check_file_heuristics(file_selected):
                quarantine_file(file_selected)
                messagebox.showinfo("Suspicious Content", f"Suspicious content found in {file_selected}. It has been quarantined.")
            else:
                messagebox.showinfo("Clean", f"{file_selected} is clean.")
        else:
            messagebox.showwarning("No File", "Please select a file to scan.")

if __name__ == "__main__":
    root = tk.Tk()
    app = AntivirusApp(root)
    root.mainloop()
#push hash
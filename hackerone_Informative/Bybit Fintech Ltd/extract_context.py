import os

def print_context(file_path, target_string, context_chars=150):
    try:
        with open(file_path, 'r', errors='ignore') as f:
            content = f.read()
        
        start_index = 0
        while True:
            idx = content.find(target_string, start_index)
            if idx == -1:
                break
            
            start_print = max(0, idx - context_chars)
            end_print = min(len(content), idx + len(target_string) + context_chars)
            
            print(f"\n--- Context for '{target_string}' in {os.path.basename(file_path)} ---")
            print(content[start_print:end_print])
            
            start_index = idx + 1
    except Exception as e:
        print(f"Error reading {file_path}: {e}")

target_file = '/media/sf_vremen/hackerone/Bybit Fintech Ltd/recon_data/globals.js'
targets = ['innerHTML']

for t in targets:
    print_context(target_file, t, context_chars=300)

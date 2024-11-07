import vt
import hashlib
import os.path
client = vt.Client("1e04fad38b5dbab7f0b18cdbc13fc54c59e91a70473683c56984676ecdb126ff")

def convert_to_md5(file_path):
    with open(file_path, 'rb') as f:
        file_hash = hashlib.md5()
        while chunk := f.read(8192):
            file_hash.update(chunk)
        return file_hash.hexdigest()
def print_malicious_rates(file):
    analysis = file.last_analysis_stats
    malicious_num = analysis['malicious']
    suspicious_num = analysis['suspicious']
    print(f"Malicious detections: {malicious_num}")
    print(f"Suspicious detections: {suspicious_num}")

def check_directory(folder_path):
    
    file_names = os.listdir(folder_path)
    for file in file_names:
        file_path = os.path.join(folder_path, file)
        if os.path.isdir(file_path):
            check_directory(file_path)
        else:
            print(file_path)
            md5_path = convert_to_md5(file_path)
            print(md5_path)
            vt_file = vt_client(md5_path)
            print(f"File {file} was detected: ")
            print_malicious_rates(vt_file)
    print(file_names)

def vt_client(md5_path):
    file = client.get_object(f"/files/{md5_path}")
    return file

folder_path_input = str(input("Please give a folder path: "))
check_directory(folder_path_input)
client.close()







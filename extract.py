import os
import pefile
import hashlib
import csv

# Get the current directory
current_dir = os.getcwd()

# Set the file path to the software folder in the current directory
file_path = os.path.join(current_dir, 'software', 'pp.8.5.Installer.x64.exe')

# Load the PE file
pe = pefile.PE(file_path)

# Calculate the MD5 hash of the file
with open(file_path, "rb") as f:
    md5_hash = hashlib.md5(f.read()).hexdigest()

# Extract the desired information
name = os.path.basename(file_path)
machine = hex(pe.FILE_HEADER.Machine)
size_of_optional_header = pe.FILE_HEADER.SizeOfOptionalHeader
characteristics = hex(pe.FILE_HEADER.Characteristics)
major_linker_version = pe.OPTIONAL_HEADER.MajorLinkerVersion
minor_linker_version = pe.OPTIONAL_HEADER.MinorLinkerVersion
size_of_code = pe.OPTIONAL_HEADER.SizeOfCode
size_of_initialized_data = pe.OPTIONAL_HEADER.SizeOfInitializedData
size_of_uninitialized_data = pe.OPTIONAL_HEADER.SizeOfUninitializedData
resources_nb = len(pe.DIRECTORY_ENTRY_RESOURCE.entries)
resources_mean_entropy = pe.sections[-1].get_entropy()

if hasattr(pe.sections[-1], 'subsections'):
    resources_min_entropy = min([s.get_entropy() for s in pe.sections[-1].subsections])
    resources_max_entropy = max([s.get_entropy() for s in pe.sections[-1].subsections])
else:
    resources_min_entropy = pe.sections[-1].get_entropy()
    resources_max_entropy = pe.sections[-1].get_entropy()

if hasattr(pe, 'resources'):
    resources_mean_size = sum([r[2] for r in pe.resources])/len(pe.resources)
    resources_min_size = min([r[2] for r in pe.resources])
    resources_max_size = max([r[2] for r in pe.resources])
else:
    resources_mean_size = 0
    resources_min_size = 0
    resources_max_size = 0

load_configuration_size = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG']].Size
version_information_size = pe.FileInfo[0].sizeof()

# Write the information to a CSV file
with open('pe_file_info.csv', mode='w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(['Name', 'md5', 'Machine', 'SizeOfOptionalHeader', 'Characteristics', 'MajorLinkerVersion', 'MinorLinkerVersion', 'SizeOfCode', 'SizeOfInitializedData', 'SizeOfUninitializedData', 'ResourcesNb', 'ResourcesMeanEntropy', 'ResourcesMinEntropy', 'ResourcesMaxEntropy', 'ResourcesMeanSize', 'ResourcesMinSize', 'ResourcesMaxSize', 'LoadConfigurationSize', 'VersionInformationSize'])
    writer.writerow([name, md5_hash, machine, size_of_optional_header, characteristics, major_linker_version, minor_linker_version, size_of_code, size_of_initialized_data, size_of_uninitialized_data, resources_nb, resources_mean_entropy, resources_min_entropy, resources_max_entropy, resources_mean_size, resources_min_size, resources_max_size, load_configuration_size, version_information_size])

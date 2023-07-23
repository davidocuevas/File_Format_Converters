import json
import pandas as pd

def extract_image_details(data):
    image_id = data.get('ImageID', '')
    diff_ids = ', '.join(data.get('DiffIDs', []))
    repo_tags = ', '.join(data.get('RepoTags', []))
    repo_digests = ', '.join(data.get('RepoDigests', []))
    return image_id, diff_ids, repo_tags, repo_digests

def extract_container_names(data):
    container_name = data.get('ImageConfig', {}).get('container', '')
    return container_name

def convert_to_csv(input_file, output_file):
    with open(input_file, 'r') as json_file:
        data = json.load(json_file)

    image_id, diff_ids, repo_tags, repo_digests = extract_image_details(data['Metadata'])
    container_name = extract_container_names(data['Metadata'])

    results = data.get('Results', [])
    vulnerabilities_list = []

    for result in results:
        vulnerabilities = result.get('Vulnerabilities', [])
        for vulnerability in vulnerabilities:
            v_data = {
                'Target': result.get('Target', ''),
                'Class': result.get('Class', ''),
                'Type': result.get('Type', ''),
                'VulnerabilityID': vulnerability.get('VulnerabilityID', ''),
                'PkgName': vulnerability.get('PkgName', ''),
                'InstalledVersion': vulnerability.get('InstalledVersion', ''),
                'FixedVersion': vulnerability.get('FixedVersion', ''),
                'SeveritySource': vulnerability.get('SeveritySource', ''),
                'PrimaryURL': vulnerability.get('PrimaryURL', ''),
                'DataSource_ID': vulnerability.get('DataSource', {}).get('ID', ''),
                'DataSource_Name': vulnerability.get('DataSource', {}).get('Name', ''),
                'DataSource_URL': vulnerability.get('DataSource', {}).get('URL', ''),
                'Title': vulnerability.get('Title', ''),
                'Description': vulnerability.get('Description', ''),
                'Severity': vulnerability.get('Severity', ''),
                'CweIDs': ', '.join(vulnerability.get('CweIDs', [])),
                'CVSS_nvd_V3Vector': vulnerability.get('CVSS', {}).get('nvd', {}).get('V3Vector', ''),
                'CVSS_nvd_V3Score': vulnerability.get('CVSS', {}).get('nvd', {}).get('V3Score', ''),
                'CVSS_redhat_V3Vector': vulnerability.get('CVSS', {}).get('redhat', {}).get('V3Vector', ''),
                'CVSS_redhat_V3Score': vulnerability.get('CVSS', {}).get('redhat', {}).get('V3Score', ''),
                'ImageID': image_id,
                'DiffIDs': diff_ids,
                'RepoTags': repo_tags,
                'RepoDigests': repo_digests,
                'ContainerName': container_name
            }
            vulnerabilities_list.append(v_data)

    df = pd.DataFrame(vulnerabilities_list)
    df.to_csv(output_file, index=False)

if __name__ == "__main__":
    input_file = input("Enter the input JSON file name: ")
    output_file = input("Enter the output CSV file name: ")
    convert_to_csv(input_file, output_file)

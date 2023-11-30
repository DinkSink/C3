import json
import re

def find_ip_addresses_and_urls(file_path):
    with open(file_path, 'r') as file:
        json_data = json.load(file)

    ip_regex = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    url_regex = r"(http|ftp|https):\/\/([\w_-]+(?:(?:\.[\w_-]+)+))([\w.,@?^=%&:\/~+#-]*[\w@?^=%&\/~+#-])"

    ip_addresses = []
    urls = []

    for item in json_data["strings"]:
        value = item["value"]
        location = item["location"]
        if re.match(ip_regex, value):
            ip_addresses.append({"location": location, "value": value})
        elif re.match(url_regex, value):
            urls.append({"location": location, "value": value})

    return ip_addresses, urls

file_path = "./strings_output_C2.json"
ip_addresses, urls = find_ip_addresses_and_urls(file_path)
print(ip_addresses)
print(urls)

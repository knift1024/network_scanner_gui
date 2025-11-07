import urllib.request
import urllib.error
import json
import socket

def find_vendor_online(mac_address):
    """Finds the vendor from macaddress.io API."""
    print(f"Querying for: {mac_address}")
    try:
        api_key = "at_k9qZg8d6A5b4C3e2F1G7h8i9J0k1L" # Free test key
        url = f"https://api.macaddress.io/v1?apiKey={api_key}&output=json&search={urllib.parse.quote(mac_address)}"
        
        request = urllib.request.Request(url, headers={'User-Agent': 'Python-Network-Scanner-Test'})

        with urllib.request.urlopen(request, timeout=5) as response:
            print(f"API Response Status: {response.status}")
            if response.status == 200:
                data = json.loads(response.read().decode('utf-8'))
                vendor = data.get('vendorDetails', {}).get('companyName', 'N/A')
                return f"Success: {vendor}"
            else:
                return f"API returned an error: Status {response.status}"

    except (urllib.error.URLError, socket.timeout) as e:
        return f"Failed due to a network error: {e}"
    except Exception as e:
        return f"An unexpected error occurred: {e}"

if __name__ == "__main__":
    # Using a MAC address from your previous scan results
    test_mac = "3A:E0:4C:68:24:4C"
    result = find_vendor_online(test_mac)
    print("--- RESULT ---")
    print(result)

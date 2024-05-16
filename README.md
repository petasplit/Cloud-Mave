Installation Instructions:
1. Install the necessary Python packages:
pip install shodan censys colorama dnspython requests pysocks

2. Install sublist3r (if not already installed):
git clone https://github.com/aboul3la/Sublist3r.git
cd Sublist3r
pip install -r requirements.txt

3. Save the script to a file (e.g., CM.py) and run it from the command line:
python3 CM.py --target example.com --shodan-api-key YOUR_SHODAN_API_KEY --censys-api-id YOUR_CENSYS_API_ID --censys-api-secret YOUR_CENSYS_API_SECRET


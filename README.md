# URL Threat Analyzer 🔍🛡️

A simple web tool to analyze URLs for potential security threats using VirusTotal and Shodan intelligence.
---

## Features
- **Risk Scoring**: 0-10 risk assessment for any URL
- **VirusTotal Integration**
- **Shodan Insights**
- **MongoDB Storage**: Saving searched url results

---

### Prerequisites
- MongoDB:
- API Keys:
  - [VirusTotal](https://www.virustotal.com/)
  - [Shodan](https://www.shodan.io/)

### Installation
1. **Clone the repo**
   ```bash
   git clone https://github.com/nikhilwilsonk/threatIntelligence.git
   cd threatIntelligence
2. **Create env and install requirement file**
    ```bash
    conda create -n **env_name** pip -y 
    conda activate **env_name**
    pip install -r requirements.txt
3. **Create an .env file**
    Create an env file to add the api keys and mongodb uri and mongodb database name
3. **Run the app**
    ```bash
    python app.py



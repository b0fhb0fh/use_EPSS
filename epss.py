#!/usr/bin/python3

import csv
import requests
import math
import logging
from typing import Optional, List, Tuple

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def fetch_epss(cve: str) -> Optional[float]:
    """Fetch the EPSS value for a given CVE."""
    url = f"https://api.first.org/data/v1/epss?cve={cve}"
    response = requests.get(url)
    
    if response.status_code != 200:
        logger.error(f"Error fetching data for {cve}: {response.status_code}")
        return None
    
    try:
        json_data = response.json()
        epss_value = float(json_data['data'][0]['epss'])
        return epss_value
    except (IndexError, KeyError, ValueError) as e:
        logger.error(f"Error parsing JSON data for {cve}: {e}")
        return None

def calculate_combined_risk(file_name: str) -> None:
    """Calculate the combined risk from a CSV file containing CVEs."""
    try:
        with open(file_name, newline='') as csvfile:
            reader = csv.reader(csvfile, delimiter=';')
            total_multiplier = 1.0
            
            for row in reader:
                cve, cvss_str, count_str = row
                try:
                    cvss = float(cvss_str)
                    count = int(count_str)
                except ValueError:
                    logger.warning(f"Invalid CVSS value '{cvss_str}' or count value '{count_str}' for {cve}")
                    continue
                
                if cvss > 8:
                    epss = fetch_epss(cve)
                    if epss is not None and epss > 0.1:
                        risk_reduction = 1 - epss
                        total_multiplier *= risk_reduction
                        logger.info(f"{cve}, {cvss}, {epss}, {risk_reduction}, {total_multiplier}")
            
            final_risk = 1 - total_multiplier
            logger.info(f"Final combined risk: {final_risk:.20f}")
    
    except FileNotFoundError:
        logger.error(f"The file '{file_name}' does not exist.")
    except Exception as e:
        logger.error(f"An error occurred: {e}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        logger.error("Usage: python script.py <filename>")
    else:
        calculate_combined_risk(sys.argv[1])

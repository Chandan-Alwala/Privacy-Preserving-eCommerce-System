# Privacy-Preserving-eCommerce-System

## Overview
This project implements a secure Privacy Preserving eCommerce System in Python, incorporating the Diffie Hellman algorithm for privacy preservation. The system consists of Customer and Merchant applications, mediated by a Broker, to facilitate secure communication while preserving user privacy. The project utilizes TCP sockets for communication and employs multi-threading to handle concurrent customer requests.

## Functionalities
- **Merchant:**
  - Add/remove eProducts to/from inventory.
  
- **Customer:**
  - Browse eProducts at the Merchant.
  - Place purchase requests for eProducts.
  
- **Broker:**
  - Mediate all communications between Customers and Merchants.
  - Preserve customer identity and payment details from the Merchant.
  - Ensure confidentiality of eProduct transactions.

## Security Requirements
### Authentication
- Customers authenticate the Merchant using Diffie Hellman.
- Both parties authenticate the Broker, and vice versa.
- Exception: Broker authenticates Customers using pre-stored Username/Password.

### Confidentiality
- Messages between Customers and Merchants are secure against passive and active attacks.
- Efficiently secure messages with the Broker to hide customer identity and payment details.
- Keyed-hash mechanism (SHA-256) for confidentiality.

### Integrity
- Detect and prevent message alteration in transit between communicating parties.
- Implement integrity verification using keyed-hash functions.

### Additional Measures
- File padding to prevent potential linking of eProducts with delivered content.

## Implementation Details
- Programming Language: Python
- Security Mechanisms:
  - Diffie Hellman for privacy preservation
  - RSA for authentication
  - Custom keyed-hash mechanism (SHA-256) for confidentiality
  - Multi-threading for concurrent customer handling

## How to Run
1. Clone the repo to a desired location
2. Ensure all installations are present. (If not, use pip install <library>).
3. Navigate to the Merchant folder and run python Merchant.py
4. Navigate to the Broker folder and run python Broker.py.
5. Navigate to the Customer<#> folder and run Customer<#>.py


## Dependencies
- Python (version >= 3.9)
- Additional cryptography libraries 

## Other Information
- Detailed implementation and screenshots are provided in the 'Final_Documentation.pdf' above. 


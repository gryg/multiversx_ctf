# MultiversX Blockchain CTF execute scripts guide

## Initial Setup

1. First, clone this repository and navigate to the project directory:
```bash
git clone https://github.com/gryg/multiversx_ctf
cd multiversx_ctf
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows, use: venv\Scripts\activate
```

3. Install the required Python packages:
```bash
pip install multiversx-sdk
pip install asyncio
```


## Wallet Setup
Have your wallet PEM file ready in the project directory. The scripts will use this file to sign transactions.

## Script Descriptions


## Running the Scripts

Each script can be run directly from the command line:

```bash
# To run the coinflip exploit
python coinflip-exploit.py

# To run the bump automation with custom parameters
python bump-automation.py [pem_path] [num_workers] [base_delay]

# To run the gas calculation exploit
python gas-calc-exp.py
```

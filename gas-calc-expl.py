from multiversx_sdk import *
from pathlib import Path
import logging
import time
import base64

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# The baseline key value from the contract
KEY_BASELINE = 12345678  # This is an example - we need the actual value

class GaspassExploiter:
    def __init__(self, pem_path: str):
        """
        Initialize exploiter with blockchain connection and wallet setup.
        
        For MultiversX smart contracts, it's required to:
        1. Properly encode function names for the ABI
        2. Calculate exact gas requirements
        3. Handle transaction creation and signing
        
        Args:
            pem_path: Path to your wallet's PEM file
        """
        # First, let's make sure our wallet file exists
        wallet_path = Path(pem_path)
        if not wallet_path.exists():
            raise FileNotFoundError(f"Wallet file not found at: {pem_path}")
            
        # Set up our connection to the MultiversX devnet
        self.proxy = ProxyNetworkProvider("https://devnet-gateway.multiversx.com")
        
        # Load our wallet - this gives us the ability to sign transactions
        logger.info(f"Loading wallet from: {wallet_path.absolute()}")
        self.signer = UserSigner.from_pem_file(wallet_path)
        
        # Store both Address objects and their bech32 representations
        self.wallet_address = Address.from_hex(self.signer.get_pubkey().hex(), "erd")
        self.wallet_address_bech32 = self.wallet_address.bech32()
        
        # Store the contract's address - this is what we'll be interacting with
        self.contract_address = Address.from_bech32(
            "erd1qqqqqqqqqqqqqpgqnqw2aep56p5hg5ksualpfwav55pvaafjd8ssg4pur0"
        )
        self.contract_address_bech32 = self.contract_address.bech32()
        
        # Set up basic network parameters
        self.chain_id = "D"  # "D" indicates devnet
        self.min_gas_price = 1000000000  # Cost per unit of computation
        
        logger.info(f"Wallet loaded successfully. Address: {self.wallet_address_bech32}")

    def calculate_personal_key(self) -> int:
        """
        Calculate our personal key by summing the bytes of our address.
        This matches the contract's personal_key calculation:
        
        fn personal_key(&self, caller: &ManagedAddress) -> u64 {
            let bytes = caller.to_byte_array();
            bytes.iter().map(|&b| b as u64).sum()
        }
        """
        address_bytes = self.wallet_address.get_public_key()
        return sum(address_bytes)

    def calculate_required_gas(self) -> int:
        """
        Calculate the exact gas needed for a successful gaspass call.
        
        The contract checks: gas_left == KEY_BASELINE + personal_key
        We need to:
        1. Calculate our personal key (sum of address bytes)
        2. Add the KEY_BASELINE
        3. Account for gas consumption before the check
        """
        personal_key = self.calculate_personal_key()
        target_gas = KEY_BASELINE + personal_key
        
        # We need to account for gas consumed before the check
        # This requires careful testing or analysis of the contract
        gas_consumed_before_check = 1000000  # needs tuning
        
        return target_gas + gas_consumed_before_check

    def execute_gaspass(self) -> str:
        """
        Execute a gaspass transaction with exactly the right amount of gas.
        
        For MultiversX smart contracts, we need to:
        1. Encode the function name properly for the ABI
        2. Set the exact gas limit we calculated
        3. Sign and send the transaction
        """
        try:
            # First, get our current account state to get the correct nonce
            account = self.proxy.get_account(self.wallet_address)
            
            # Calculate the exact gas we need
            gas_limit = self.calculate_required_gas()
            
            # Properly encode the function call for the ABI
            # @ indicates function call
            function_call = "@6761737370617373"  # "gaspass" in hex with @ prefix
            
            # Create transaction with exact gas and encoded function call
            tx = Transaction(
                nonce=account.nonce,
                value="0",
                sender=self.wallet_address_bech32,
                receiver=self.contract_address_bech32,
                gas_price=self.min_gas_price,
                gas_limit=gas_limit,
                chain_id=self.chain_id,
                data=function_call.encode(),
                version=1
            )
            
            # Get the message that needs to be signed
            message_to_sign = TransactionComputer().compute_bytes_for_signing(tx)
            
            # Sign the message and attach the signature
            tx.signature = self.signer.sign(message_to_sign)
            
            # Send the signed transaction to the network
            tx_hash = self.proxy.send_transaction(tx)
            logger.info(f"Transaction sent! Hash: {tx_hash}")
            return tx_hash
            
        except Exception as e:
            logger.error(f"Failed to execute gaspass: {e}")
            raise

def main(pem_path: str):
    """
    Main execution loop that tries to solve the gaspass challenge.
    
    This challenge requires:
    1. Proper function call encoding for the MultiversX ABI
    2. Exact gas calculation to match the contract's requirements
    3. Careful transaction preparation and signing
    """
    try:
        exploiter = GaspassExploiter(pem_path)
        logger.info("Starting gaspass exploit...")
        
        attempts = 0
        
        while True:
            print("\nExecuting gaspass attempt...")
            try:
                tx_hash = exploiter.execute_gaspass()
                attempts += 1
                
                print("Waiting for transaction confirmation...")
                time.sleep(6)  # Wait for the blockchain to process our transaction
                
                # Check transaction status
                status = exploiter.proxy.get_transaction_status(tx_hash)
                
                if status == "success":
                    print(f"Gaspass successful! Attempts: {attempts}")
                    break
                else:
                    print(f"Transaction status: {status}")
                    
            except Exception as e:
                print(f"Failed to execute gaspass: {e}")
            
            # Wait before next attempt - useful if we're tuning the gas value
            time.sleep(1)
            
    except Exception as e:
        logger.error(f"Exploit failed: {e}")
        raise

if __name__ == "__main__":
    wallet_path = "./wallet.pem" 
    main(wallet_path)
from multiversx_sdk import *
from pathlib import Path
import logging
import time

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# The baseline key value from the contract
KEY_BASELINE = 11000000  # found the actual value

class GaspassExploiter:
    def __init__(self, pem_path: str):
        """
        Initialize exploiter with blockchain connection and wallet setup.
        
        The key to this exploit is calculating the exact gas needed based on:
        1. The contract's KEY_BASELINE constant
        2. Our wallet address bytes
        3. Understanding gas consumption mechanics
        
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
            "erd1qqqqqqqqqqqqqpgquvpnteagc5xsslc3yc9hf6um6n6jjgzdd8ss07v9ma"
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
        gas_consumed_before_check = 1000000  # Example - needs tuning
        
        return target_gas + gas_consumed_before_check

    def execute_gaspass(self) -> str:
        """
        Execute a gaspass transaction with exactly the right amount of gas.
        
        The key is setting the gas_limit to precisely what we calculated,
        so that gas_left matches what the contract expects.
        """
        try:
            # First, get our current account state to get the correct nonce
            account = self.proxy.get_account(self.wallet_address)
            
            # Calculate the exact gas we need
            gas_limit = self.calculate_required_gas()
            
            # Create transaction with exact gas
            tx = Transaction(
                nonce=account.nonce,
                value="0",
                sender=self.wallet_address_bech32,
                receiver=self.contract_address_bech32,
                gas_price=self.min_gas_price,
                gas_limit=gas_limit,
                chain_id=self.chain_id,
                data="gaspass".encode(),
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
    
    The key to this challenge is understanding:
    1. How the contract calculates its target gas value
    2. How much gas is consumed before the check
    3. Setting our transaction's gas limit precisely
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
    wallet_path = "./wallet.pem"  # Make sure your wallet.pem is in this location
    main(wallet_path)
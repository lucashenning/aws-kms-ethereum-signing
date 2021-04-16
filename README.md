# AWS KMS based Ethereum Tx Signing
This repo shows how to sign an Ethereum transaction using AWS KMS. 

## Medium
Please see my [medium article](https://luhenning.medium.com/the-dark-side-of-the-elliptic-curve-signing-ethereum-transactions-with-aws-kms-in-javascript-83610d9a6f81) for a detailed code walk-through. 

## Prep
1. Create ECDSA secp256k1 key in AWS KMS
2. Create AWS IAM user with programmatic access to AWS KMS.
3. For the Tx to go through, you need to provide a valid web3 provider (e.g. Infura)
4. Run the script to generate the Ethereum address and fund the Ethereum account to pay for the transaction gas.

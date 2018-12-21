# Vault Plugin: Stellar Secrets Backend

This is a backend secrets plugin to be used with Hashicorp Vault. This plugin manages secret keys for the Stellar blockchain platform.

## Usage

Assuming you have Hashicorp Vault installed, `scripts/dev.sh` is a helper script to start up Vault in dev mode and mount this plugin.
Vault will be listening on a private IP at 192.168.50.4:8200.

Once the plugin is mounted, you can start writing secrets to it.

### Log In To Vault

```
export VAULT_ADDR=http://192.168.50.4:8200
vault login
```


The token is "root" if you've used dev.sh to start Vault.

### Creating an Account

`vault write stellar/accounts/MyAccountName xlm_balance=50`

This will create a new account called "MyAccountName". The XLM balance is just a placeholder for now, 
it doesn't actually do anything since we're running on the Stellar testnet.

### Viewing an Account

`vault read stellar/accounts/MyAccountName`

### Viewing All Account Names

`vault list stellar/accounts`

### Creating a Signed Payment Transaction

`vault write stellar/payments source=MySourceAccountName destination=MyDestinationAccountName amount=35`

This will return a signed transaction with a payment operation to send 35 XLM from MySourceAccountName to MyDestinationAccountName.

### Creating a Signed Payment Transaction Using a Payment Channel

`vault write stellar/payments source=MySourceAccountName destination=MyDestinationAccountName paymentChannel=MyPaymentChannelAccountName amount=35`

This will return a signed transaction with a payment operation to send 35 XLM from MySourceAccountName to MyDestinationAccountName. 
The account MyPaymentChannelAccountName will be used for sequence numbers, and 
will be added as a signer to the transaction.

## Running Tests

```
cd stellar
go test
```


## License

Copyright (c) 2018 Participate Crypto LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at:

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

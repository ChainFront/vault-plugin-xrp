/*
 * Copyright (c) 2019 ChainFront LLC.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package xrp

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"github.com/rubblelabs/ripple/data"
	"math/big"
	"strings"
)

// Register the callbacks for the paths exposed by these functions
func paymentsPaths(b *backend) []*framework.Path {
	return []*framework.Path{
		&framework.Path{
			Pattern:      "payments",
			HelpSynopsis: "Make a payment on the Ripple network",
			Fields: map[string]*framework.FieldSchema{
				"source": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Source account",
				},
				"destination": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Destination account",
				},
				"paymentChannel": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "(Optional) Payment channel account",
				},
				"additionalSigners": &framework.FieldSchema{
					Type:        framework.TypeCommaStringSlice,
					Description: "(Optional) Array of additional signers for this transaction",
				},
				"amount": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Amount to send",
				},
				"assetCode": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Code of asset to send (use 'native' for XRP)",
				},
				"assetIssuer": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "(Optional) If paying with a non-native asset, this is the issuer address",
				},
				"memo": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "(Optional) An optional memo to include with the payment transaction",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.CreateOperation: b.createPayment,
				logical.UpdateOperation: b.createPayment,
			},
		},
	}
}

// RIPPLE: Creates a signed transaction with a payment operation.
func (b *backend) createPayment(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	// Validate we didn't get extra fields
	err := validateFields(req, d)
	if err != nil {
		return nil, logical.CodedError(400, err.Error())
	}

	// Validate required fields are present
	source := d.Get("source").(string)
	if source == "" {
		return errMissingField("source"), nil
	}

	destination := d.Get("destination").(string)
	if destination == "" {
		return errMissingField("destination"), nil
	}

	amountStr := d.Get("amount").(string)
	if amountStr == "" {
		return errMissingField("amount"), nil
	}
	amount := validNumber(amountStr)

	assetCode := d.Get("assetCode").(string)
	if assetCode == "" {
		return errMissingField("assetCode"), nil
	}

	// Read optional fields
	assetIssuer := d.Get("assetIssuer").(string)
	if assetIssuer == "" && !strings.EqualFold(assetCode, "native") {
		return errMissingField("assetIssuer"), nil
	}

	// Read the optional additionalSigners field
	//var additionalSigners []string
	//if additionalSignersRaw, ok := d.GetOk("additionalSigners"); ok {
	//	additionalSigners = additionalSignersRaw.([]string)
	//}

	// Read the optional memo field
	//memo := d.Get("memo").(string)

	// Retrieve the source account keypair from vault storage
	sourceAccount, err := b.readVaultAccount(ctx, req, "accounts/"+source)
	if err != nil {
		return nil, err
	}
	if sourceAccount == nil {
		return nil, logical.CodedError(400, "source account not found")
	}
	sourceAddress := sourceAccount.AccountId

	// Retrieve the destination account keypair from vault storage
	destinationAccount, err := b.readVaultAccount(ctx, req, "accounts/"+destination)
	if err != nil {
		return nil, err
	}
	if destinationAccount == nil {
		return nil, logical.CodedError(400, "destination account not found")
	}
	destinationAddress := destinationAccount.AccountId

	// Prepare the payment transaction
	payment, err := createPaymentTransaction(sourceAddress, destinationAddress, amount.String(), assetCode, assetIssuer)
	if err != nil {
		return nil, err
	}

	// Sign the transaction
	signedPayment, err := signPaymentTransaction(sourceAccount, payment)
	if err != nil {
		return nil, err
	}

	_, txRaw, err := data.Raw(signedPayment)
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"source_address":     signedPayment.Account.String(),
			"account_sequence":   signedPayment.Sequence,
			"fee":                signedPayment.Fee.String(),
			"transaction_hash":   signedPayment.Hash.String(),
			"signed_transaction": fmt.Sprintf("%X", txRaw),
		},
	}, nil
}

func (b *backend) validAccountConstraints(account *Account, amount *big.Int, toAddress string) (bool, error) {
	txLimit := validNumber(account.TxSpendLimit)

	if txLimit.Cmp(amount) == -1 && txLimit.Cmp(big.NewInt(0)) == 1 {
		return false, fmt.Errorf("transaction amount (%s) is larger than the transactional limit (%s)", amount.String(), account.TxSpendLimit)
	}

	if contains(account.Blacklist, toAddress) {
		return false, fmt.Errorf("%s is blacklisted", toAddress)
	}

	if len(account.Whitelist) > 0 && !contains(account.Whitelist, toAddress) {
		return false, fmt.Errorf("%s is not in the whitelist", toAddress)
	}

	return true, nil
}

// Create a new unsigned payment transaction
func createPaymentTransaction(sourceAddress string, destinationAddress string, amount string, assetCode string, assetIssuer string) (*data.Payment, error) {
	src, err := data.NewAccountFromAddress(sourceAddress)
	if err != nil {
		return nil, err
	}

	dest, err := data.NewAccountFromAddress(destinationAddress)
	if err != nil {
		Log(err)
		return nil, err
	}

	// Convert the amount into an object
	var amountObj *data.Amount
	if strings.EqualFold(assetCode, "native") {
		amountObj, err = data.NewAmount(amount + "/XRP")
		if err != nil {
			Log(err)
			return nil, err
		}
	} else {
		amountObj, err = data.NewAmount(amount + "/" + assetCode + "/" + assetIssuer)
		if err != nil {
			return nil, logical.CodedError(400, "invalid currency code or issuer")
		}
	}

	// Create payment
	payment := &data.Payment{
		Destination: *dest,
		Amount:      *amountObj,
	}
	payment.TransactionType = data.PAYMENT

	payment.Flags = new(data.TransactionFlag)

	fee, err := data.NewNativeValue(int64(10))
	base := payment.GetBase()
	base.Fee = *fee
	//base.Memos = new data.Memo{}
	base.Account = *src

	return payment, nil
}

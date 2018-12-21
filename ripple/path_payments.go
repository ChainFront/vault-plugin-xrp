package ripple

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"github.com/rubblelabs/ripple/crypto"
	"github.com/rubblelabs/ripple/data"
	"github.com/rubblelabs/ripple/websockets"
	"math/big"
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
					Description: "Code of asset to send (use 'native' for XLM)",
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
	payment, err := createPaymentTransaction(sourceAddress, destinationAddress, amount.String())
	if err != nil {
		return nil, err
	}

	// Sign the transaction
	signedPayment, err := signTransaction(sourceAccount, payment)
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
func createPaymentTransaction(sourceAddress string, destinationAddress string, amount string) (*data.Payment, error) {
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
	amountObj, err := data.NewAmount(amount + "/XRP")
	if err != nil {
		Log(err)
		return nil, err
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
	base.Account = *src

	return payment, nil
}

// Sign a payment transaction
func signTransaction(account *Account, payment *data.Payment) (*data.Payment, error) {
	// Get the signer key and sequence
	seed, err := crypto.NewRippleHashCheck(account.Secret, crypto.RIPPLE_FAMILY_SEED)
	if err != nil {
		return nil, err
	}
	key, err := crypto.NewECDSAKey(seed.Payload())

	rippleAccount, err := data.NewAccountFromAddress(account.AccountId)
	if err != nil {
		return nil, err
	}

	remote, err := websockets.NewRemote("wss://s.altnet.rippletest.net:51233")
	if err != nil {
		return nil, err
	}

	accountInfo, err := remote.AccountInfo(*rippleAccount)
	if err != nil {
		return nil, err
	}
	sequence := accountInfo.AccountData.Sequence

	base := payment.GetBase()
	base.Sequence = *sequence

	// Sign the payment transaction
	keySequence := uint32(0)
	err = data.Sign(payment, key, &keySequence)
	if err != nil {
		return nil, err
	}

	return payment, nil
}

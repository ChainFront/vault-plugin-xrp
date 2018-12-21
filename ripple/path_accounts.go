package ripple

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"github.com/rubblelabs/ripple/crypto"
	"github.com/rubblelabs/ripple/websockets"
	"github.com/shopspring/decimal"
	"io"
	"log"
	"net/http"
)

type ecdsaKey struct {
	*btcec.PrivateKey
}

// Account is a Ripple account
type Account struct {
	AccountId    string   `json:"account_id"`
	PublicKey    string   `json:"public_key"`
	PrivateKey   string   `json:"private_key"`
	Secret       string   `json:"secret"`
	TxSpendLimit string   `json:"tx_spend_limit"`
	Whitelist    []string `json:"whitelist"`
	Blacklist    []string `json:"blacklist"`
}

func accountsPaths(b *backend) []*framework.Path {
	return []*framework.Path{
		&framework.Path{
			Pattern: "accounts/?",
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ListOperation: b.pathListAccounts,
			},
		},
		&framework.Path{
			Pattern:      "accounts/" + framework.GenericNameRegex("name"),
			HelpSynopsis: "Create a new Ripple account",
			Fields: map[string]*framework.FieldSchema{
				"name": &framework.FieldSchema{Type: framework.TypeString},
				"xrp_balance": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "(Optional) Initial starting balance of XRP",
				},
				"source_account_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "(Optional) Account used to fund the starting balance",
				},
				"tx_spend_limit": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "(Optional) Maximum amount of tokens which can be sent in a single transaction",
					Default:     "0",
				},
				"whitelist": &framework.FieldSchema{
					Type:        framework.TypeCommaStringSlice,
					Description: "(Optional) The list of accounts that this account can transact with.",
				},
				"blacklist": &framework.FieldSchema{
					Type:        framework.TypeCommaStringSlice,
					Description: "(Optional) The list of accounts that this account is forbidden from transacting with.",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.CreateOperation: b.pathCreateAccount,
				logical.UpdateOperation: b.pathCreateAccount,
				logical.ReadOperation:   b.pathReadAccount,
			},
		},
	}
}

// Returns a list of stored accounts (does not validate that the account is valid on Ripple)
func (b *backend) pathListAccounts(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	accountList, err := req.Storage.List(ctx, "accounts/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(accountList), nil
}

// Generates and stores an secp256k1 asymmetric key pair
func (b *backend) pathCreateAccount(ctx context.Context, req *logical.Request, d *framework.FieldData) (response *logical.Response, err error) {
	// Validate we didn't get extra fields
	//err := validateFields(req, d)
	//if err != nil {
	//	return nil, logical.CodedError(422, err.Error())
	//}

	// Read optional fields
	var whitelist []string
	if whitelistRaw, ok := d.GetOk("whitelist"); ok {
		whitelist = whitelistRaw.([]string)
	}
	var blacklist []string
	if blacklistRaw, ok := d.GetOk("blacklist"); ok {
		blacklist = blacklistRaw.([]string)
	}

	txSpendLimitString := d.Get("tx_spend_limit").(string)
	txSpendLimit, err := decimal.NewFromString(txSpendLimitString)
	if err != nil || txSpendLimit.IsNegative() {
		return nil, fmt.Errorf("tx_spend_limit is either not a number or is negative")
	}

	// Generate a random secp256k1 (unable to use ed25519 due to bugs in Ripple re: payment channel signing)
	rawSeed := make([]byte, 16)
	_, err = io.ReadFull(rand.Reader, rawSeed[:])
	if err != nil {
		return nil, err
	}

	ecdsaKey, err := crypto.NewECDSAKey(rawSeed)
	if err != nil {
		Log(err)
		return nil, err
	}

	seedHash, err := crypto.NewFamilySeed(rawSeed)
	if err != nil {
		Log(err)
		return nil, err
	}

	publicKeyBytes := ecdsaKey.PubKey().SerializeCompressed()
	publicKeyHash, err := crypto.NewAccountPublicKey(publicKeyBytes)
	if err != nil {
		Log(err)
		return nil, err
	}

	privateKeyBytes := ecdsaKey.D.Bytes()
	privateKeyHash, err := crypto.NewAccountPrivateKey(privateKeyBytes)
	if err != nil {
		return nil, err
	}

	// Create a Ripple account id from the public key
	accountIdBytes := sha256RipeMD160(publicKeyBytes)
	accountIdHash, err := crypto.NewAccountId(accountIdBytes)
	if err != nil {
		Log(err)
		return nil, err
	}

	accountIdStr := accountIdHash.String()

	// Prod anchor
	//err = fundAccount(address)

	// Testnet
	err = fundTestAccount(accountIdStr)
	if err != nil {
		Log(err)
		return nil, err
	}

	// Create and store an Account object in Vault
	accountJSON := &Account{
		AccountId:    accountIdStr,
		PublicKey:    publicKeyHash.String(),
		PrivateKey:   privateKeyHash.String(),
		Secret:       seedHash.String(),
		TxSpendLimit: txSpendLimit.String(),
		Whitelist:    whitelist,
		Blacklist:    blacklist}

	entry, err := logical.StorageEntryJSON(req.Path, accountJSON)
	if err != nil {
		Log(err)
		return nil, err
	}

	err = req.Storage.Put(ctx, entry)
	if err != nil {
		Log(err)
		return nil, err
	}

	log.Printf("successfully created account %v", accountJSON.AccountId)

	return &logical.Response{
		Data: map[string]interface{}{
			"accountId":    accountJSON.AccountId,
			"publicKey":    accountJSON.PublicKey,
			"txSpendLimit": txSpendLimit.String(),
			"whitelist":    whitelist,
			"blacklist":    blacklist,
		},
	}, nil
}

// Returns account details for the given account
func (b *backend) pathReadAccount(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	vaultAccount, err := b.readVaultAccount(ctx, req, req.Path)
	if err != nil {
		log.Fatal(err)
		return nil, fmt.Errorf("error reading account")
	}
	if vaultAccount == nil {
		return nil, nil
	}

	publicKey := &vaultAccount.PublicKey
	whitelist := &vaultAccount.Whitelist
	blacklist := &vaultAccount.Blacklist
	accountId := &vaultAccount.AccountId
	txSpendLimit := &vaultAccount.TxSpendLimit

	return &logical.Response{
		Data: map[string]interface{}{
			"accountId":    accountId,
			"publicKey":    publicKey,
			"txSpendLimit": txSpendLimit,
			"whitelist":    whitelist,
			"blacklist":    blacklist,
		},
	}, nil
}

func (b *backend) readVaultAccount(ctx context.Context, req *logical.Request, path string) (*Account, error) {
	log.Print("Reading account from path: " + path)
	entry, err := req.Storage.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to read account at %s", path)
	}
	if entry == nil || len(entry.Value) == 0 {
		return nil, nil
	}

	var account Account
	err = entry.DecodeJSON(&account)

	if entry == nil {
		return nil, fmt.Errorf("failed to deserialize account at %s", path)
	}

	return &account, err
}

// Using the Ripple testnet faucet, create a funded test account, then transfer them to our new test account
func fundTestAccount(address string) (err error) {
	faucetAddress, faucetSecret, err := generateTestFaucetAccount()
	if err != nil {
		Log(err)
		return err
	}

	// Send the XRP over to our target address
	payment, err := createPaymentTransaction(faucetAddress, address, "1000")
	if err != nil {
		Log(err)
		return err
	}

	faucetAccount := &Account{
		AccountId: faucetAddress,
		Secret:    faucetSecret}

	signedTx, err := signTransaction(faucetAccount, payment)
	if err != nil {
		Log(err)
		return err
	}

	remote, err := websockets.NewRemote("wss://s.altnet.rippletest.net:51233")
	if err != nil {
		Log(err)
		return err
	}

	submitResult, err := remote.Submit(signedTx)
	if err != nil {
		Log(err)
		return err
	}
	log.Printf("Submitted transaction result : %s -- %s", submitResult.EngineResult.String(), submitResult.EngineResultMessage)

	return nil
}

func generateTestFaucetAccount() (string, string, error) {
	resp, err := http.Post("https://faucet.altnet.rippletest.net/accounts", "application/json", nil)
	Fatal(err, "Unable to POST to Ripple TestNet faucet endpoint")
	defer resp.Body.Close()

	type Account struct {
		Address string
		Secret  string
	}

	type Container struct {
		Account Account
		Balance string
	}

	result := &Container{}

	json.NewDecoder(resp.Body).Decode(&result)

	faucetAddress := result.Account.Address
	faucetSecret := result.Account.Secret

	log.Print("Generated faucet account '" + faucetAddress + "' with secret '" + faucetSecret + "'")

	return faucetAddress, faucetSecret, nil
}
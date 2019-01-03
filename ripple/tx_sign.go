package ripple

import (
	"github.com/rubblelabs/ripple/crypto"
	"github.com/rubblelabs/ripple/data"
	"github.com/rubblelabs/ripple/websockets"
)

// Sign a payment transaction
func signPaymentTransaction(account *Account, payment *data.Payment) (*data.Payment, error) {
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

// Sign a accountset transaction
func signAccountSetTransaction(account *Account, accountSet *data.AccountSet) (*data.AccountSet, error) {
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

	base := accountSet.GetBase()
	base.Sequence = *sequence

	// Sign the transaction
	keySequence := uint32(0)
	err = data.Sign(accountSet, key, &keySequence)
	if err != nil {
		return nil, err
	}

	return accountSet, nil
}

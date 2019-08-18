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
	"github.com/rubblelabs/ripple/crypto"
	"github.com/rubblelabs/ripple/data"
	"github.com/rubblelabs/ripple/websockets"
)

// Sign a payment transaction
func signPaymentTransaction(account *Account, paymentTx *data.Payment) (*data.Payment, error) {
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

	base := paymentTx.GetBase()
	base.Sequence = *sequence

	// Sign the payment transaction
	keySequence := uint32(0)
	err = data.Sign(paymentTx, key, &keySequence)
	if err != nil {
		return nil, err
	}

	return paymentTx, nil
}

// Sign a accountset transaction
func signAccountSetTransaction(account *Account, accountSetTx *data.AccountSet) (*data.AccountSet, error) {
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

	base := accountSetTx.GetBase()
	base.Sequence = *sequence

	// Sign the transaction
	keySequence := uint32(0)
	err = data.Sign(accountSetTx, key, &keySequence)
	if err != nil {
		return nil, err
	}

	return accountSetTx, nil
}

// Sign a trustset transaction
func signTrustSetTransaction(account *Account, trustSetTx *data.TrustSet) (*data.TrustSet, error) {
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

	base := trustSetTx.GetBase()
	base.Sequence = *sequence

	// Sign the transaction
	keySequence := uint32(0)
	err = data.Sign(trustSetTx, key, &keySequence)
	if err != nil {
		return nil, err
	}

	return trustSetTx, nil
}

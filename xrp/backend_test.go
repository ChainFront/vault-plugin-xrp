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
	"bytes"
	"context"
	"encoding/hex"
	"github.com/rubblelabs/ripple/data"
	"github.com/rubblelabs/ripple/websockets"
	"testing"
	"time"

	"fmt"
	"github.com/hashicorp/vault/logical"
)

const (
	defaultLeaseTTLHr = 1
	maxLeaseTTLHr     = 12
)

// Set up/Teardown
type testData struct {
	B      logical.Backend
	S      logical.Storage
	Remote websockets.Remote
}

func setupTest(t *testing.T) *testData {
	b, reqStorage := getTestBackend(t)
	rippleRemote, err := websockets.NewRemote("wss://s.altnet.rippletest.net:51233")
	if err != nil {
		t.Fatalf("Unable to connect to Ripple testnet: %v", err)
	}
	return &testData{
		B:      b,
		S:      reqStorage,
		Remote: *rippleRemote,
	}
}

func getTestBackend(t *testing.T) (logical.Backend, logical.Storage) {
	b := Backend()

	config := &logical.BackendConfig{
		System: &logical.StaticSystemView{
			DefaultLeaseTTLVal: defaultLeaseTTLHr * time.Hour,
			MaxLeaseTTLVal:     maxLeaseTTLHr * time.Hour,
		},
		StorageView: &logical.InmemStorage{},
	}
	err := b.Setup(context.Background(), config)
	if err != nil {
		t.Fatalf("unable to create backend: %v", err)
	}

	return b, config.StorageView
}

func TestBackend_createAccount(t *testing.T) {

	td := setupTest(t)

	accountName := "account1"
	createAccount(td, accountName, t)
}

func TestBackend_createAccountWithFlags(t *testing.T) {

	td := setupTest(t)

	accountName := "account1"
	createAccount(td, accountName, t)

	respData := createAccountSet(td, accountName, "8", "", "chainfront.io", t)

	signedTx, ok := respData["signed_transaction"]
	if !ok {
		t.Fatalf("expected signedTx data not present in createAccountSet")
	}

	submitSignedTransaction(td, signedTx, t)
}

func TestBackend_createAccountWithTrustline(t *testing.T) {

	td := setupTest(t)

	// Create our issuing account
	issuerAccountName := "issuingAccount"
	createAccount(td, issuerAccountName, t)

	// Set the DefaultRipple flag on the issuing account
	respData := createAccountSet(td, issuerAccountName, "8", "", "chainfront.io", t)
	issuerAddress := respData["source_address"]
	signedTx, ok := respData["signed_transaction"]
	if !ok {
		t.Fatalf("expected signedTx data not present in createAccountSet")
	}
	submitSignedTransaction(td, signedTx, t)

	// Create our user account
	userAccountName := "userAccount"
	createAccount(td, userAccountName, t)

	// Establish a trustline to our custom currency
	trustSetData := createAccountTrustSet(td, userAccountName, "SRC", issuerAddress.(string), "1000000", t)
	signedTrustSetTx, ok := trustSetData["signed_transaction"]
	if !ok {
		t.Fatalf("expected signedTx data not present in createAccountTrustSet")
	}
	submitSignedTransaction(td, signedTrustSetTx, t)
}

func TestBackend_submitPayment(t *testing.T) {

	td := setupTest(t)
	createAccount(td, "testSourceAccount", t)
	createAccount(td, "testDestinationAccount", t)

	respData := createPayment(td, "testSourceAccount", "testDestinationAccount", "35", t)

	signedTx, ok := respData["signed_transaction"]
	if !ok {
		t.Fatalf("expected signedTx data not present in createPayment")
	}

	decodedString, err := hex.DecodeString(signedTx.(string))
	if err != nil {
		t.Fatalf("unable to decode signedTx: %v", err)
	}

	byteReader := bytes.NewReader(decodedString)
	transaction, err := data.ReadTransaction(byteReader)
	if err != nil {
		Log(err)
		t.Fatalf("unable to read signed_transaction as a valid Ripple transaction: %v", err)
	}

	response, err := td.Remote.Submit(transaction)
	if err != nil {
		t.Fatalf("failed to submit transaction to testnet: %v", err)
	}

	t.Logf("Submitted transaction result : %s -- %s", response.EngineResult.String(), response.EngineResultMessage)
}

func TestBackend_submitPaymentAboveLimit(t *testing.T) {

	td := setupTest(t)
	createAccount(td, "testSourceAccount", t)
	createAccount(td, "testDestinationAccount", t)

	respData := createPayment(td, "testSourceAccount", "testDestinationAccount", "1001", t)

	signedTx, ok := respData["signed_transaction"]
	if !ok {
		t.Fatalf("expected signedTx data not present in createPayment")
	}

	decodedString, err := hex.DecodeString(signedTx.(string))
	if err != nil {
		t.Fatalf("unable to decode signedTx: %v", err)
	}

	byteReader := bytes.NewReader(decodedString)
	transaction, err := data.ReadTransaction(byteReader)
	if err != nil {
		Log(err)
		t.Fatalf("unable to read signed_transaction as a valid Ripple transaction: %v", err)
	}

	response, err := td.Remote.Submit(transaction)
	if err != nil {
		t.Fatalf("failed to submit transaction to testnet: %v", err)
	}

	t.Logf("Submitted transaction result : %s -- %s", response.EngineResult.String(), response.EngineResultMessage)
}

func createAccount(td *testData, accountName string, t *testing.T) {
	d :=
		map[string]interface{}{
			"xrp_balance":    "50",
			"tx_spend_limit": "1000",
		}
	resp, err := td.B.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      fmt.Sprintf("accounts/%s", accountName),
		Data:      d,
		Storage:   td.S,
	})
	if err != nil {
		t.Fatalf("failed to create account: %v", err)
	}
	if resp.IsError() {
		t.Fatal(resp.Error())
	}
	if resp == nil {
		t.Fatal("response is nil")
	}
	t.Log(resp.Data)
}

func createAccountSet(td *testData, sourceAccountName string, setFlag string, clearFlag string, domain string, t *testing.T) map[string]interface{} {
	d :=
		map[string]interface{}{
			"set_flag":   setFlag,
			"clear_flag": clearFlag,
			"domain":     domain,
		}
	resp, err := td.B.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      fmt.Sprintf("accounts/%s/accountset", sourceAccountName),
		Data:      d,
		Storage:   td.S,
	})
	if err != nil {
		t.Fatalf("failed to set account flags: %v", err)
	}
	if resp.IsError() {
		t.Fatal(resp.Error())
	}
	if resp == nil {
		t.Fatal("response is nil")
	}
	t.Log(resp.Data)

	return resp.Data
}

func createAccountTrustSet(td *testData, sourceAccountName string, currencyCode string, issuer string, limit string, t *testing.T) map[string]interface{} {
	d :=
		map[string]interface{}{
			"currencyCode": currencyCode,
			"issuer":       issuer,
			"limit":        limit,
		}
	resp, err := td.B.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      fmt.Sprintf("accounts/%s/trustline", sourceAccountName),
		Data:      d,
		Storage:   td.S,
	})
	if err != nil {
		t.Fatalf("failed to create trustline: %v", err)
	}
	if resp.IsError() {
		t.Fatal(resp.Error())
	}
	if resp == nil {
		t.Fatal("response is nil")
	}
	t.Log(resp.Data)

	return resp.Data
}

func createPayment(td *testData, sourceAccountName string, destinationAccountName string, amount string, t *testing.T) map[string]interface{} {
	d :=
		map[string]interface{}{
			"source":      sourceAccountName,
			"destination": destinationAccountName,
			"assetCode":   "native",
			"amount":      amount,
		}
	resp, err := td.B.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      fmt.Sprintf("payments"),
		Data:      d,
		Storage:   td.S,
	})
	if err != nil {
		t.Fatalf("failed to create payment: %v", err)
	}
	if resp.IsError() {
		t.Fatal(resp.Error())
	}
	if resp == nil {
		t.Fatal("response is nil")
	}
	t.Log(resp.Data)

	return resp.Data
}

func submitSignedTransaction(td *testData, signedTx interface{}, t *testing.T) *websockets.SubmitResult {
	decodedString, err := hex.DecodeString(signedTx.(string))
	if err != nil {
		t.Fatalf("unable to decode signedTx: %v", err)
	}
	byteReader := bytes.NewReader(decodedString)
	transaction, err := data.ReadTransaction(byteReader)
	if err != nil {
		Log(err)
		t.Fatalf("unable to read signed_transaction as a valid Ripple transaction: %v", err)
	}
	response, err := td.Remote.Submit(transaction)
	if err != nil {
		t.Fatalf("failed to submit transaction to testnet: %v", err)
	}
	t.Logf("Submitted transaction result : %s -- %s", response.EngineResult.String(), response.EngineResultMessage)
	return response
}

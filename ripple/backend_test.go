package ripple

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
		t.Fatalf("failed to submit transaction to testnet: %v", errorString(err))
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
		t.Fatalf("failed to submit transaction to testnet: %v", errorString(err))
	}

	t.Logf("Submitted transaction result : %s -- %s", response.EngineResult.String(), response.EngineResultMessage)
}

func TestBackend_submitPaymentUsingChannel(t *testing.T) {

	td := setupTest(t)
	createAccount(td, "testSourceAccount", t)
	createAccount(td, "testDestinationAccount", t)
	createAccount(td, "testPaymentChannelAccount", t)

	respData := createPaymentWithChannel(td, "testSourceAccount", "testDestinationAccount", "testPaymentChannelAccount", "35", t)

	signedTx, ok := respData["signed_transaction"]
	if !ok {
		t.Fatalf("expected signedTx data not present in createPayment")
	}

	byteReader := bytes.NewReader([]byte(signedTx.(string)))
	transaction, err := data.ReadTransaction(byteReader)
	if err != nil {
		t.Fatalf("unable to read signed_transaction as a valid Ripple transaction: %v", err)
	}

	response, err := td.Remote.Submit(transaction)
	if err != nil {
		t.Fatalf("failed to submit transaction to testnet: %v", errorString(err))
	}

	t.Logf("transaction posted in ledger: %v", response.EngineResultMessage)
}

func TestBackend_submitPaymentUsingChannelAndAdditionalSigners(t *testing.T) {

	td := setupTest(t)
	createAccount(td, "testSourceAccount", t)
	createAccount(td, "testDestinationAccount", t)
	createAccount(td, "testPaymentChannelAccount", t)
	createAccount(td, "testAdditionalSigner1Account", t)
	createAccount(td, "testAdditionalSigner2Account", t)

	var additionalSigners []string
	additionalSigners = append(additionalSigners, "testAdditionalSigner1Account", "testAdditionalSigner2Account")

	respData := createPaymentWithChannelAndAdditionalSigners(td, "testSourceAccount", "testDestinationAccount", "testPaymentChannelAccount", additionalSigners, "35", t)

	signedTx, ok := respData["signed_transaction"].(string)
	if !ok {
		t.Fatalf("expected signedTx data not present in createPayment")
	}

	byteReader := bytes.NewReader([]byte(signedTx))
	transaction, err := data.ReadTransaction(byteReader)
	if err != nil {
		Log(err)
		t.Fatalf("unable to read signed_transaction as a valid Ripple transaction: %v", err)
	}

	response, err := td.Remote.Submit(transaction)
	if err != nil {
		Log(err)
		t.Fatalf("failed to submit transaction to testnet: %v", errorString(err))
	}

	t.Logf("transaction posted in ledger: %v", response.EngineResultMessage)
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

func createPaymentWithChannel(td *testData, sourceAccountName string, destinationAccountName string, paymentChannelAccountName string, amount string, t *testing.T) map[string]interface{} {
	d :=
		map[string]interface{}{
			"source":         sourceAccountName,
			"destination":    destinationAccountName,
			"paymentChannel": paymentChannelAccountName,
			"assetCode":      "native",
			"amount":         amount,
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

func createPaymentWithChannelAndAdditionalSigners(td *testData, sourceAccountName string, destinationAccountName string, paymentChannelAccountName string, additionalSigners []string, amount string, t *testing.T) map[string]interface{} {
	d :=
		map[string]interface{}{
			"source":            sourceAccountName,
			"destination":       destinationAccountName,
			"paymentChannel":    paymentChannelAccountName,
			"additionalSigners": additionalSigners,
			"assetCode":         "native",
			"amount":            amount,
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

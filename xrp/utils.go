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
	"crypto/sha256"
	"fmt"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ripemd160"
	"log"
	"math/big"
	"regexp"
	"sort"
)

func contains(stringSlice []string, searchString string) bool {
	for _, value := range stringSlice {
		if value == searchString {
			return true
		}
	}
	return false
}

// validNumber returns a valid positive integer
func validNumber(input string) *big.Int {
	if input == "" {
		return big.NewInt(0)
	}
	matched, err := regexp.MatchString("([0-9])", input)
	if !matched || err != nil {
		return nil
	}
	amount := math.MustParseBig256(input)
	return amount.Abs(amount)
}

// validateFields verifies that no bad arguments were given to the request.
func validateFields(req *logical.Request, data *framework.FieldData) error {
	var unknownFields []string
	for k := range req.Data {
		if _, ok := data.Schema[k]; !ok {
			unknownFields = append(unknownFields, k)
		}
	}

	if len(unknownFields) > 0 {
		// Sort since this is a human error
		sort.Strings(unknownFields)

		return fmt.Errorf("unknown fields: %q", unknownFields)
	}

	return nil
}

// errMissingField returns a logical response error that prints a consistent
// error message for when a required field is missing.
func errMissingField(field string) *logical.Response {
	return logical.ErrorResponse(fmt.Sprintf("Missing required field '%s'", field))
}

func sha256RipeMD160(b []byte) []byte {
	ripe := ripemd160.New()
	sha := sha256.New()
	sha.Write(b)
	ripe.Write(sha.Sum(nil))
	return ripe.Sum(nil)
}

// ZeroKey removes the key from memory
func ZeroKey(k *ecdsaKey) {
	b := k.D.Bits()
	for i := range b {
		b[i] = 0
	}
}

//Fatal panics on error
//First parameter of msgs is used each following variadic arg is dropped
func Fatal(err error, msgs ...string) {
	if err != nil {
		var str string
		for _, msg := range msgs {
			str = msg
			break
		}
		panic(errors.Wrap(err, str))
	}
}

//Recover recovers a panic introduced by Fatal, any other function which calls panics
//				or a memory corruption. Logs the error when called without args.
//
//Must be used at the top of the function defered
//defer Recover()
//or
//defer Recover(&err)
func Recover(errs ...*error) {
	var e *error
	for _, err := range errs {
		e = err
		break
	}

	//handle panic
	if r := recover(); r != nil {
		var errmsg error
		//Preserve error which might have happend before panic/recover
		//Check if a error ptr was passed + a error occured
		if e != nil && *e != nil {
			//When error occured before panic then Wrap panic error around it
			errmsg = errors.Wrap(*e, r.(error).Error())
		} else {
			//No error occured just add a stacktrace
			errmsg = errors.Wrap(r.(error), "")
		}

		//If error cant't bubble up -> Log it
		if e != nil {
			*e = errmsg
		} else {
			log.Printf("%+v", errmsg)
		}
	}
}

//Log logs an error + stack trace directly to console or file
//Use this at the top level to publish errors without creating a new error object
func Log(err error, msgs ...string) {
	if err != nil {
		var str string
		for _, msg := range msgs {
			str = msg
			break
		}
		log.Printf("%+v", errors.Wrap(err, str))
	}
}

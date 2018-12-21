package ripple

import (
	"context"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"github.com/pkg/errors"
)

type backend struct {
	*framework.Backend
}

// Factory creates a new usable instance of this secrets engine.
func Factory(ctx context.Context, c *logical.BackendConfig) (logical.Backend, error) {
	b := Backend()
	if err := b.Setup(ctx, c); err != nil {
		return nil, errors.Wrap(err, "Unable to set up Ripple secret backend")
	}
	return b, nil
}

func Backend() *backend {
	var b backend
	b.Backend = &framework.Backend{
		Help: "",
		Paths: framework.PathAppend(
			accountsPaths(&b),
			paymentsPaths(&b)),
		PathsSpecial: &logical.Paths{},
		Secrets:      []*framework.Secret{},
		BackendType:  logical.TypeLogical,
	}
	return &b
}

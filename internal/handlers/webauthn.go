package handlers

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/authelia/authelia/v4/internal/middlewares"
	"github.com/authelia/authelia/v4/internal/model"
	"github.com/authelia/authelia/v4/internal/random"
)

const (
	WebAuthnExtensionCredProps            = "credProps"
	WebAuthnExtensionCredPropsResidentKey = "rk"
	WebAuthnDiscoverable                  = "discoverable"
)

const (
	webauthnCredentialDescriptionMaxLen = 64
)

func formatWebAuthnError(err error) error {
	out := &protocol.Error{}

	if errors.As(err, &out) {
		if len(out.DevInfo) == 0 {
			return err
		}

		if len(out.Type) == 0 {
			return fmt.Errorf("%w: %s", err, out.DevInfo)
		}

		return fmt.Errorf("%w (%s): %s", err, out.Type, out.DevInfo)
	}

	return err
}

func handleGetWebAuthnUserByRPID(ctx *middlewares.AutheliaCtx, username, displayname string, rpid string) (user *model.WebAuthnUser, err error) {
	if user, err = ctx.Providers.StorageProvider.LoadWebAuthnUser(ctx, rpid, username); err != nil {
		return nil, err
	}

	if user == nil {
		user = &model.WebAuthnUser{
			RPID:        rpid,
			Username:    username,
			UserID:      ctx.Providers.Random.StringCustom(64, random.CharSetASCII),
			DisplayName: displayname,
		}

		if err = ctx.Providers.StorageProvider.SaveWebAuthnUser(ctx, *user); err != nil {
			return nil, err
		}
	} else {
		user.DisplayName = displayname
	}

	if user.DisplayName == "" {
		user.DisplayName = user.Username
	}

	if user.Credentials, err = ctx.Providers.StorageProvider.LoadWebAuthnCredentialsByUsername(ctx, rpid, user.Username); err != nil {
		return nil, err
	}

	return user, nil
}

func handleNewWebAuthn(ctx *middlewares.AutheliaCtx) (w *webauthn.WebAuthn, err error) {
	var (
		origin *url.URL
	)

	if origin, err = ctx.GetOrigin(); err != nil {
		return nil, err
	}

	config := &webauthn.Config{
		RPID:                  origin.Hostname(),
		RPDisplayName:         ctx.Configuration.WebAuthn.DisplayName,
		RPOrigins:             []string{origin.String()},
		AttestationPreference: ctx.Configuration.WebAuthn.ConveyancePreference,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			AuthenticatorAttachment: ctx.Configuration.WebAuthn.SelectionCriteria.Attachment,
			ResidentKey:             ctx.Configuration.WebAuthn.SelectionCriteria.Discoverability,
			UserVerification:        ctx.Configuration.WebAuthn.SelectionCriteria.UserVerification,
		},
		Debug:                false,
		EncodeUserIDAsString: true,
		Timeouts: webauthn.TimeoutsConfig{
			Login: webauthn.TimeoutConfig{
				Enforce:    true,
				Timeout:    ctx.Configuration.WebAuthn.Timeout,
				TimeoutUVD: ctx.Configuration.WebAuthn.Timeout,
			},
			Registration: webauthn.TimeoutConfig{
				Enforce:    true,
				Timeout:    ctx.Configuration.WebAuthn.Timeout,
				TimeoutUVD: ctx.Configuration.WebAuthn.Timeout,
			},
		},
		MDS: ctx.Providers.MetaDataService,
	}

	switch ctx.Configuration.WebAuthn.SelectionCriteria.Attachment {
	case protocol.Platform, protocol.CrossPlatform:
		config.AuthenticatorSelection.AuthenticatorAttachment = ctx.Configuration.WebAuthn.SelectionCriteria.Attachment
	}

	switch ctx.Configuration.WebAuthn.SelectionCriteria.Discoverability {
	case protocol.ResidentKeyRequirementRequired:
		config.AuthenticatorSelection.RequireResidentKey = protocol.ResidentKeyRequired()
	default:
		config.AuthenticatorSelection.RequireResidentKey = protocol.ResidentKeyNotRequired()
	}

	ctx.Logger.Tracef("Creating new WebAuthn RP instance with ID %s and Origins %s", config.RPID, strings.Join(config.RPOrigins, ", "))

	return webauthn.New(config)
}

func handleWebAuthnCredentialCreationIsDiscoverable(ctx *middlewares.AutheliaCtx, response *protocol.ParsedCredentialCreationData) (discoverable bool) {
	if value, ok := response.ClientExtensionResults[WebAuthnExtensionCredProps]; ok {
		switch credentialProperties := value.(type) {
		case map[string]any:
			var v any

			if v, ok = credentialProperties[WebAuthnExtensionCredPropsResidentKey]; ok {
				if discoverable, ok = v.(bool); ok {
					ctx.Logger.WithFields(map[string]any{WebAuthnDiscoverable: discoverable}).Trace("Determined Credential Discoverability via Client Extension Results")

					return discoverable
				} else {
					ctx.Logger.WithFields(map[string]any{WebAuthnDiscoverable: false}).Trace("Assuming Credential Discoverability is false as the 'rk' field for the 'credProps' extension in the Client Extension Results was not a boolean")
				}
			} else {
				ctx.Logger.WithFields(map[string]any{WebAuthnDiscoverable: false}).Trace("Assuming Credential Discoverability is false as the 'rk' field for the 'credProps' extension was missing from the Client Extension Results")
			}

			return false
		default:
			ctx.Logger.WithFields(map[string]any{WebAuthnDiscoverable: false}).Trace("Assuming Credential Discoverability is false as the 'credProps' extension in the Client Extension Results does not appear to be a dictionary")

			return false
		}
	}

	ctx.Logger.WithFields(map[string]any{WebAuthnDiscoverable: false}).Trace("Assuming Credential Discoverability is false as the 'credProps' extension is missing from the Client Extension Results")

	return false
}

func handlerWebAuthnDiscoverableLogin(ctx *middlewares.AutheliaCtx, rpid string) webauthn.DiscoverableUserHandler {
	return func(rawID, userHandle []byte) (user webauthn.User, err error) {
		var u *model.WebAuthnUser

		if u, err = ctx.Providers.StorageProvider.LoadWebAuthnUserByUserID(ctx, rpid, string(userHandle)); err != nil {
			return nil, err
		}

		if u.Credentials, err = ctx.Providers.StorageProvider.LoadWebAuthnPasskeyCredentialsByUsername(ctx, rpid, u.Username); err != nil {
			return nil, err
		}

		return u, nil
	}
}

func checkWebAuthnCredentialAllowed(ctx *middlewares.AutheliaCtx, credential *model.WebAuthnCredential) (err error) {
	if len(ctx.Configuration.WebAuthn.Filtering.PermittedAAGUIDs) != 0 {
		for _, aaguid := range ctx.Configuration.WebAuthn.Filtering.PermittedAAGUIDs {
			if credential.AAGUID.UUID == aaguid {
				return nil
			}
		}
		return fmt.Errorf("error checking webauthn AAGUID: filters have been configured which explicitly require only permitted AAGUID's be used and '%s' is not permitted", credential.AAGUID.UUID)
	}

	for _, aaguid := range ctx.Configuration.WebAuthn.Filtering.ProhibitedAAGUIDs {
		if credential.AAGUID.UUID == aaguid {
			return fmt.Errorf("error checking webauthn AAGUID: filters have been configured which prohibit the AAGUID '%s' from registration", aaguid)
		}
	}

	return nil
}

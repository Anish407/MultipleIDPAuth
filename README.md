# Infrastructure Authentication PoC

Evaluate infrastructure-enforced authentication for this architecture:

```text
WPF → CloudFront → VPC Origin → Private ALB → ECS Fargate / .NET API
```

The IdP authenticates the user, WPF obtains credentials in the token approach, ALB enforces request authentication, and the backend owns authorization and business rules. See [project context](../PROJECT_CONTEXT.md) for the requirements and full lab scope.

## Lab guides

| Lab | Scope | Documentation |
|---|---|---|
| 1 | Shared OIDC client with Entra; later ALB JWT enforcement | [Configure Entra ID for the WPF app](labs/lab-1-entra-wpf/README.md) |
| 2 | Reuse the Lab 1 client with Cognito configuration | Guide to be added when this lab starts |
| 3 | ALB-managed OIDC login and WPF sessions with Entra | Guide to be added when this lab starts |
| 4 | Repeat the ALB session experiment with Cognito | Guide to be added when this lab starts |

Only the current Entra/WPF setup has a detailed guide. Lab 1 is still in progress; successful token acquisition does not by itself prove ALB authentication enforcement.

## Shared implementation

Build one provider-neutral OIDC client in Lab 1 using Duende.IdentityModel.OidcClient. Lab 2 changes provider configuration and reuses that code. Each deployment uses one IdP.

- [WPF client](MultipleIDPAuth.Client/)
- [API project](MultipleAuthAPi.API1/)
- [Solution](MultipleIDPAuth.slnx)

## Documentation structure

```text
README.md                              # Project overview and lab index
labs/
  lab-1-entra-wpf/
    README.md                          # Entra registrations and WPF setup
```

Add separate lab README files as those labs are implemented, then link them from this index. Document verified results and outstanding work within the relevant guide.

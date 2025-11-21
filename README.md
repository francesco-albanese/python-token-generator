# Token Generator
This script creates a public/private RSA256 key pair, stores the keys in `certificates` folder, and formats the public key in JWKs format.

## Prerequisites
- Copy .env.example and rename it into .env
- populate the `CONNECTION_ID` value with your connection ID
- Example: `CONNECTION_ID=1062`
- Follow the make commands below to install the dependencies and run the script

### View All Available Make Targets

```bash
make help
```

### How to use
Run
```bash
make install-deps
```
to setup your development environment, installing `uv` package manager and downloading the dependencies.

Run
```bash
make generate-token
```
to generate the JWT and see it printed in the console


# ATLAS-H2020 demo service bundle

This is a web application that exposes several demonstration ATLAS services. These services are not suitable for production purposes but provide ATLAS-compliant APIs on a fixed set of data and can therefore be used in the initial development cycle of an ATLAS-enabled Digital System.

Note that OAUth2 base authentication is properly implemented. You may use this service as a template for your own full-fledged ATLAS service.

## Services currently included in the bundle
- field_data
- sensor_data

These service are nearly 100% compliant with their respective ATLAS Service Templates, although they are based on "hard-coded" data, without dynamic storage capabilities.

## Run with docker compose
Clone the repo:

    git clone git@github.com:atlasH2020/demo_service_bundle.git

Launch with docker-compose: 

    cd demo_service_bundle
    docker-compose build
    docker-compose up

## Test

The default authorization server which may be used "out of the box" has the following configuration parameters:

| parameter     | value                                                                     |
|---------------|---------------------------------------------------------------------------|
| Callback URL  | http://localhost:8000/auth/callback                                       |
| Auth URL      | https://agricircle-test.auth.us-east-2.amazoncognito.com/oauth2/authorize |
| Token URL     | https://agricircle-test.auth.us-east-2.amazoncognito.com/oauth2/token     |
| Client ID     | 7l4tup7uhdipg237qp455a7j7                                                 |
| Client Secret | 1okp4i4dl3lpl8g2hfp7302iiiqrurdqaockpgkdibska22n54ko                      |
| Scope         | openid                                                                    |

which can be used to obtain an OAuth2 access token (e.g. with Postman), using the pre-configured **atlas@demo.com** user with password: **atlas_demo**.

A published version of the demo service bundle is published in the ATLAS service registry.
FLASK_APP=api.main:create_app
JWT_ISSUER=https://cognito-idp.us-east-2.amazonaws.com/us-east-2_53a2KyBTh
JWT_JWKS_URI=https://cognito-idp.us-east-2.amazonaws.com/us-east-2_53a2KyBTh/.well-known/jwks.json
PYTHONUNBUFFERED=1
cd src && flask run --host=0.0.0.0 --port=8000
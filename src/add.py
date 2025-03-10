import boto3
import uuid
import random
import json
import string
import utils
import os
import logger
from module import session, tenant_table, role_table, policy_table

REGION = os.environ.get('REGION', 'us-east-1')
CLIENT = boto3.client('cognito-idp', region_name=REGION)
USER_POOL_ID = os.environ.get('USER_POOL_ID', '')

def lambda_handler(event, context):
    payload = json.loads(event['body'])
    print("Payload:::", payload)
    logger.debug("Payload for create user", data=payload)

    tenant_id = str(uuid.uuid4())
    role_id = str(uuid.uuid4())
    policy_id = str(uuid.uuid4())

    # Determine username: prefer phone number if both are provided

    if 'phone_number' in payload:
        username = payload['phone_number']
    elif 'email' in payload:
        username = payload['email']
    else:
        return utils.generate_out_put_response({}, "Either email or phone number must be provided", 400)

    # Check if user already exists
    if user_exists(username, USER_POOL_ID):
        logger.warning("User already exists")
        return utils.generate_out_put_response({}, "User already exists", 400)

    try:
        # Generate a temporary password
        temporary_password = get_random_password()
        logger.debug("Temporary password for user", data=username)

        # Prepare user attributes
        user_attributes = [
            {'Name': 'name', 'Value': payload['name']},
            {'Name': 'custom:tenantId', 'Value': tenant_id},
            {'Name': 'custom:isPremiumUser', 'Value': 'false'}
        ]

        # Always add email and phone if provided
        if 'email' in payload:
            user_attributes.append({'Name': 'email', 'Value': payload['email']})
            user_attributes.append({'Name': 'email_verified', 'Value': "true"})
        if 'phone_number' in payload:
            user_attributes.append({'Name': 'phone_number', 'Value': payload['phone_number']})
            user_attributes.append({'Name': 'phone_number_verified', 'Value': "true"})

        # Create the user in Cognito
        response = CLIENT.admin_create_user(
            UserPoolId=USER_POOL_ID,
            Username=username,  # Uses phone number if available, otherwise email
            TemporaryPassword=temporary_password,
            UserAttributes=user_attributes
        )

        sub_value = None
        for attribute in response['User']['Attributes']:
            if attribute['Name'] == 'sub':
                sub_value = attribute['Value']
                break

        # Default permission settings
        default_permission = {
            "vendor": ["get"],
            "order": ["post", "get"]
        }

        # Database records for the new user
        account_creation = [
            {
                "id": tenant_id,
                "tenant_name": payload['name'],
                "created_by": tenant_id,
                "role_name": "superAdmin",
                "table_name": tenant_table,
            },
            {
                "id": role_id,
                "role_name": "superAdmin",
                "tenant_id": tenant_id,
                "created_by": tenant_id,
                "table_name": role_table,
            },
            {
                "id": policy_id,
                "role_id": role_id,
                "tenant_id": tenant_id,
                "policy": default_permission,
                "created_by": tenant_id,
                "table_name": policy_table,
            },
        ]
        logger.debug("Database payload for account creation", data=account_creation)

        # Insert user records into the database
        for user_data in account_creation:
            table_name = user_data.pop("table_name")
            insert_record = utils.insert_table_record(
                session, user_data, table_name
            )

        logger.debug("User created successfully", data={"username": username})
        return utils.generate_out_put_response(
            {"username": username}, "User created successfully", 200
        )

    except Exception as error:
        logger.error(f"Error in create user: {error}")
        return utils.generate_out_put_response({}, "Error creating user", 400)


def get_random_password():
    """Generate a secure random password."""
    random_source = string.ascii_letters + string.digits
    password = (
        random.choice(string.ascii_lowercase) +
        random.choice(string.ascii_uppercase) +
        random.choice(string.digits) +
        random.choice('$@!%') +
        ''.join(random.choice(random_source) for i in range(4))
    )
    password_list = list(password)
    random.SystemRandom().shuffle(password_list)
    return ''.join(password_list)


def user_exists(username, USER_POOL_ID):
    """Check if a user already exists in Cognito."""
    try:
        CLIENT.admin_get_user(
            UserPoolId=USER_POOL_ID,
            Username=username
        )
        return True
    except CLIENT.exceptions.UserNotFoundException:
        return False
    except Exception as e:
        logger.error(f"Error checking user existence: {e}")
        return False
 
import boto3
import datetime
import json
import os
import time

# Create AWS clients
s3_client = boto3.client('s3')
sts_client = boto3.client('sts')
acm_client = boto3.client('acm')

# Number of days before certificate expiry to notify
notify_if_expires_after = int(os.environ['notifyIfExpiresAfter'])

# Bucket name for storing data
bucket = os.environ['BUCKETNAME']

def lambda_handler(event, context):
    # Initialize message
    message = "Account_ID ,Account Name ,Certificate ID,Domain_Name ,SANs ,Expires_in, Requested_date, Status, Expires_on, InUse"

    # Get account dictionary from environment variable
    account_dict_json = os.environ['accountDict']
    account_dict = json.loads(account_dict_json)

    # Iterate through account dictionary
    for key in account_dict.keys():
        data = get_cert_details(str(key), account_dict[str(key)])
        message += data
        print(message)

    # Upload message to S3
    current_date = time.strftime("%Y-%m-%d", time.gmtime())
    key_name = 'Certs_expiry_data_' + current_date + '.csv'
    s3_client.put_object(Bucket=bucket, Key=key_name, Body=message)
  
def get_cert_details(account_id, account_name):
    data = ""
    assumed_role_object = sts_client.assume_role(
        RoleArn="arn:aws:iam::" + account_id + ":role/crossaccount-acmaccessrole-demo",
        RoleSessionName="AssumeRoleSession1_" + account_id
    )
    credentials = assumed_role_object['Credentials']

    client = boto3.client('acm',
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken']
    )
    
    certificate_list = client.list_certificates()["CertificateSummaryList"]
    now = datetime.datetime.now()

    for certificate in certificate_list:
        certificate_details = client.describe_certificate(CertificateArn=certificate["CertificateArn"])["Certificate"]

        if 'NotAfter' in certificate_details:
            certificate_expires_in = certificate_details['NotAfter'].replace(tzinfo=None) - now

            if certificate_expires_in <= datetime.timedelta(days=notify_if_expires_after):
                data += "\n" + "=(\"" + account_id + "\")" + "," + account_name + "," + \
                    repr(certificate_details['CertificateArn']).replace("'arn:aws:acm:us-west-2:" + account_id + ":certificate/", "").replace("'", "") + \
                    "," + certificate_details['DomainName'].replace("'", "") + \
                    "," + repr(certificate_details['SubjectAlternativeNames']).replace(",", ":") + \
                    "," + repr(certificate_expires_in.days) + " days" + \
                    "," + str(certificate_details['CreatedAt'].year) + "/" + str(certificate_details['CreatedAt'].month) + "/" + str(certificate_details['CreatedAt'].day) + \
                    "," + repr(certificate_details['Status']) + \
                    "," + str(certificate_details['NotAfter'].year) + "/" + str(certificate_details['NotAfter'].month) + "/" + str(certificate_details['NotAfter'].day)

                if len(certificate_details['InUseBy']) > 0:
                    data += ",Yes"
                else:
                    data += ",No"

    return data
